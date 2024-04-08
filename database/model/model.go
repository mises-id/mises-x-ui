package model

import (
	"fmt"
	"x-ui/util/json_util"
	"x-ui/xray"
)

type Protocol string

const (
	VMess       Protocol = "vmess"
	VLESS       Protocol = "vless"
	Dokodemo    Protocol = "Dokodemo-door"
	Http        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
)

type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Inbound struct {
	Id           int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	UserId       int    `json:"-"`
	Up           int64  `json:"up" form:"up"`
	Down         int64  `json:"down" form:"down"`
	Total        int64  `json:"total" form:"total"`
	Remark       string `json:"remark" form:"remark"`
	Enable       bool   `json:"enable" form:"enable"`
	ExpiryTime   int64  `json:"expiryTime" form:"expiryTime"`
	MisesOrderId string `json:"-"`
	MisesLink    string `json:"-"`

	// config part
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port" gorm:"unique"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`
}

type InboundSettings struct {
	Clients                   []map[string]interface{} `json:"clients"`
	DisableInsecureEncryption bool                     `json:"disableInsecureEncryption"`
}

type TlsSettings struct {
	ServerName   string        `json:"serverName"`
	Certificates []interface{} `json:"certificates"`
	Alpn         []interface{} `json:"alpn"`
}

type XtlsSettings struct {
	ServerName   string        `json:"serverName"`
	Certificates []interface{} `json:"certificates"`
	Alpn         []interface{} `json:"alpn"`
}

type TcpHeader struct {
	Type     string      `json:"type"`
	Request  interface{} `json:"request,omitempty"`
	Response interface{} `json:"response,omitempty"`
}

type TcpSettings struct {
	AcceptProxyProtocol bool       `json:"acceptProxyProtocol"`
	Header              *TcpHeader `json:"header"`
}

type KcpHeader struct {
	Type string `json:"type"`
}

type KcpSettings struct {
	Mtu              int64      `json:"mtu"`
	Tti              int64      `json:"tti"`
	UplinkCapacity   int64      `json:"uplinkCapacity"`
	DownlinkCapacity int64      `json:"downlinkCapacity"`
	Congestion       bool       `json:"congestion"`
	ReadBufferSize   int64      `json:"readBufferSize"`
	WriteBufferSize  int64      `json:"writeBufferSize"`
	Header           *KcpHeader `json:"header"`
	Seed             string     `json:"seed"`
}

type WsSettings struct {
	AcceptProxyProtocol bool        `json:"acceptProxyProtocol"`
	Path                string      `json:"path"`
	Headers             interface{} `json:"headers"`
}

type HttpSettings struct {
	Path string   `json:"path"`
	Host []string `json:"host"`
}

type QuicHeader struct {
	Type string `json:"type"`
}

type QuicSettings struct {
	Security string      `json:"security"`
	Key      string      `json:"key"`
	Header   *QuicHeader `json:"header"`
}

type GrpcSettings struct {
	ServiceName string `json:"serviceName"`
}

type InboundStreamSettings struct {
	Network      string        `json:"network"`
	Security     string        `json:"security"`
	TlsSettings  *TlsSettings  `json:"tlsSettings,omitempty"`
	XtlsSettings *XtlsSettings `json:"xtlsSettings,omitempty"`
	TcpSettings  *TcpSettings  `json:"tcpSettings,omitempty"`
	KcpSettings  *KcpSettings  `json:"kcpSettings,omitempty"`
	WsSettings   *WsSettings   `json:"wsSettings,omitempty"`
	HttpSettings *HttpSettings `json:"httpSettings,omitempty"`
	QuicSettings *QuicSettings `json:"quicSettings,omitempty"`
	GrpcSettings *GrpcSettings `json:"grpcSettings,omitempty"`
}

type InboundSniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	if listen != "" {
		listen = fmt.Sprintf("\"%v\"", listen)
	}
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       string(i.Protocol),
		Settings:       json_util.RawMessage(i.Settings),
		StreamSettings: json_util.RawMessage(i.StreamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
	}
}

type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}
