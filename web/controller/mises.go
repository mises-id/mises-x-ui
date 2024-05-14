package controller

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"strings"
	"time"
	"x-ui/config"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/util"
	"x-ui/util/random"
	"x-ui/web/entity"
	"x-ui/web/service"
)

const (
	MisesApiUserId       int            = 0
	//MisesMinPort         int            = 10000
	//MisesMaxPort         int            = 60000
	MisesMinPort         int            = 56000
	MisesMaxPort         int            = 56500
	MisesDefaultRemark   string         = "mises_user"
	MisesDefaultProtocol model.Protocol = model.VMess
	MisesDefaultNetwork  string         = "tcp"
)

type AddInboundParam struct {
	UserId     string `json:"userId"`
	OrderId    string `json:"orderId"`
	ExpiryTime int64  `json:"expiryTime"`
}

type GetInboundsParam struct {
	UserId     string `json:"userId"`
}

type DelInboundsParam struct {
	UserIds    []string `json:"userIds"`
}

type MisesController struct {
	inboundService service.InboundService
	xrayService    service.XrayService
}

func NewMisesController(g *gin.RouterGroup) *MisesController {
	a := &MisesController{}
	a.initRouter(g)
	return a
}

func (a *MisesController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/mises")
	g.Use(a.auth)

	g.POST("/get_inbounds", a.getInbounds)
	g.POST("/add_inbounds", a.addInbound)
	g.POST("/del_inbounds", a.delInbounds)
}

func (a *MisesController) auth(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.Error("request body error:", err)
		c.JSON(http.StatusInternalServerError, entity.Msg{
			Success: false,
			Msg: "request body error",
		})
		c.Abort()
		return
	}

	if err := verifySignature(body, c.GetHeader("X-Api-Signature")); err != nil {
		logger.Error("signature error:", err)
		c.JSON(http.StatusInternalServerError, entity.Msg{
			Success: false,
			Msg: "signature error",
		})
		c.Abort()
		return
	}

	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	c.Next()
}

func verifySignature(messageBytes []byte, sig string) error {
	// The signature to verify, which should be base64-encoded
	signature, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return err
	}

	// Hash the original message
	hashed := sha256.Sum256(messageBytes)

	// Verify the signature
	err = rsa.VerifyPKCS1v15(config.Envs.MisesPublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return err
	}

	// success
	return nil
}

func (a *MisesController) getInbounds(c *gin.Context) {
	param := new(GetInboundsParam)
	err := c.ShouldBindJSON(param)
	if err != nil {
		jsonMsg(c, "获取", err)
		return
	}

	if param.UserId == "" {
		jsonMsg(c, "获取", errors.New("param error"))
		return
	}

	ms, err := a.inboundService.GetInboundByTag(genMisesTag(param.UserId))
	if err != nil {
		jsonMsg(c, "获取", err)
		return
	}
	jsonObj(c, ms, nil)
}

func (a *MisesController) addInbound(c *gin.Context) {
	param := new(AddInboundParam)
	err := c.ShouldBind(param)
	if err != nil {
		logger.Errorf("ShouldBindJSON:", err)
		jsonMsg(c, "添加", err)
		return
	}
	if param.UserId == "" || param.OrderId == "" || param.ExpiryTime == 0  {
		logger.Errorf("param check:", errors.New("params error"))
		jsonMsg(c, "添加", errors.New("params error"))
		return
	}

	// retry for 5 times
	for i := 0; i < 5; i++ {
		// check whether user id exists
		tag := genMisesTag(param.UserId)
		ms, err := a.inboundService.GetInboundByTag(tag)
		if err != nil {
			jsonMsg(c, "检查inbound", err)
			return
		}
		if len(ms) > 0 {
			if ms[0].MisesOrderId != param.OrderId && ms[0].ExpiryTime < param.ExpiryTime {
				// update OrderId and ExpiryTime
				err := a.inboundService.UpdateMisesInbound(ms[0].Id, param.OrderId, param.ExpiryTime)
				if err != nil {
					logger.Errorf("UpdateMisesInbound:", err)
					time.Sleep(1 * time.Second)
					continue
				}
			}
			jsonObj(c, ms[0].MisesLink, nil)
			return
		} else {
			inbound, err := a.generateNewInbound(c)
			if err != nil {
				logger.Error("generateNewInbound:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			inbound.UserId = MisesApiUserId
			inbound.Enable = true
			inbound.Tag = genMisesTag(param.UserId)
			inbound.ExpiryTime = param.ExpiryTime
			inbound.MisesOrderId = param.OrderId
			if err := a.inboundService.AddInbound(inbound); err != nil {
				logger.Errorf("AddInbound error:%v, inbound:%v", err, inbound)
				time.Sleep(1 * time.Second)
				continue
			} else {
				//if err := a.xrayService.UpsertInboundInProcess(inbound); err != nil {
				//	jsonMsg(c, "api add inbound", err)
				//	return
				//}
				jsonObj(c, inbound.MisesLink, nil)
				return
			}
		}
	}

	//if err == nil {
	//	a.xrayService.SetToNeedRestart()
	//}

	// default failure
	jsonMsg(c, "添加", err)
}

func (a *MisesController) generateNewInbound(c *gin.Context) (*model.Inbound, error) {
	// port
	port, err := a.generateRandomPort()
	if err != nil {
		return nil, err
	}

	// uuid
	uuid, err := util.GetUuid()
	if err != nil {
		return nil, err
	}

	// inbound
	inbound := &model.Inbound{}
	inbound.Up = 0
	inbound.Down = 0
	inbound.Total = 0
	inbound.Remark = MisesDefaultRemark
	inbound.Listen = ""
	inbound.Port = port
	inbound.Protocol = MisesDefaultProtocol

	// inbound.Settings
	inboundSettings := new(model.InboundSettings)
	inboundSettings.Clients = make([]map[string]interface{}, 0, 1)
	newClient := map[string]interface{}{
		"id": uuid,
		"alterId": 0,
	}
	inboundSettings.Clients = append(inboundSettings.Clients, newClient)
	inboundSettings.DisableInsecureEncryption = false
	bs, err := json.Marshal(inboundSettings)
	if err != nil {
		return nil, err
	}
	inbound.Settings = string(bs)

	// inbound.StreamSettings
	inboundStreamSettings := new(model.InboundStreamSettings)
	inboundStreamSettings.Network = MisesDefaultNetwork
	inboundStreamSettings.Security = "none"
	inboundStreamSettings.TcpSettings = &model.TcpSettings{
		Header: &model.TcpHeader{
			Type: "none",
		},
	}
	bs, err = json.Marshal(inboundStreamSettings)
	if err != nil {
		return nil, err
	}
	inbound.StreamSettings = string(bs)

	// inbound.Sniffing
	inboundSniffing := new(model.InboundSniffing)
	inboundSniffing.Enabled = true
	inboundSniffing.DestOverride = []string{"http", "tls"}
	bs, err = json.Marshal(inboundSniffing)
	if err != nil {
		return nil, err
	}
	inbound.Sniffing = string(bs)

	// MisesLink
	link, err := genVmessLink(inbound, c, uuid)
	if err != nil {
		return nil, err
	}
	inbound.MisesLink = link

	// result
	return inbound, nil
}

func (a *MisesController) generateRandomPort() (int, error) {
	// retry for 5 times
	for i := 0; i < 5; i ++ {
		port := random.RandomIntRange(MisesMinPort, MisesMaxPort)
		b, err := a.inboundService.CheckPortExist(port)
		if err != nil {
			return 0, err
		}
		if b {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return port, nil
	}
	return 0, errors.New("fail to generate new port")
}

func genVmessLink(inbound *model.Inbound, c *gin.Context, uuid string) (string, error) {
	if inbound == nil || c == nil || uuid == "" {
		return "", fmt.Errorf("genVmessLink error, inbound:%v, gin.Context:%v, uuid:%s", inbound, c, uuid)
	}
	address := config.Envs.ServerForVpnLink
	if address == "" {
		ss := strings.Split(c.Request.Host, ":")
		if len(ss) > 0 {
			address = ss[0]
		} else {
			return "", fmt.Errorf("genVmessLink error, c.Request.Host:%s", c.Request.Host)
		}
	}

	// todo: 需确认该配置是否适用于生产环境
	link := map[string]interface{}{
		"v": "2",
		"ps": inbound.Remark,
		"add": address,
		"port": inbound.Port,
		"id": uuid,
		"aid": 0,
		"net": "tcp",
		"type": "none",
		"host": "",
		"path": "",
		"tls": "none",
	}

	// result
	bs, err := json.Marshal(link)
	if err != nil {
		return "", err
	}
	sb := strings.Builder{}
	sb.WriteString("vmess://")
	sb.WriteString(base64.StdEncoding.EncodeToString(bs))
	return sb.String(), nil
}

func (a *MisesController) delInbounds(c *gin.Context) {
	param := new(DelInboundsParam)
	err := c.ShouldBindJSON(param)
	if err != nil {
		jsonMsg(c, "删除", err)
		return
	}
	if len(param.UserIds) == 0 {
		jsonMsg(c, "删除", errors.New("empty params"))
		return
	}
	tags := make([]string, 0, len(param.UserIds))
	for _, userId := range param.UserIds {
		tags = append(tags, genMisesTag(userId))
	}
	if err := a.inboundService.DelInboundsByTags(tags); err != nil {
		jsonMsg(c, "删除", err)
		return
	}

	// set to restart
	a.xrayService.SetToNeedRestart()

	jsonObj(c, nil, nil)
}

func genMisesTag(tagName string) string {
	return fmt.Sprintf("inbound-mises-%s", tagName)
}
