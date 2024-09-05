package main

import (
	"errors"
	"github.com/google/uuid"
	"log"
	"net/http"
	"time"
)

var authedMap = make(map[string]struct{})

var faceAuthedMap = make(map[string]struct{})

type event int

type Event struct {
	ID    string `json:"id,omitempty"`
	Event event  `json:"event,omitempty"`
}

const (
	WafHeaderKey = "Waf-Key-Id"
)

const (
	//通过事件返回200
	Pass event = iota
	//触发人脸识别事件
	FaceValid
	//跳转至人脸识别界面事件
	NeedFaceValid
	//拦截事件
	Reject
)

func EmitEvent(req *http.Request) Event {

	cookie, err := req.Cookie(WafHeaderKey)

	if err != nil && errors.Is(err, http.ErrNoCookie) {
		return Event{
			ID:    uuid.NewString(),
			Event: NeedFaceValid,
		}
	}

	if _, ok := authedMap[cookie.Value]; !ok {
		return Event{
			ID:    uuid.NewString(),
			Event: NeedFaceValid,
		}

	}

	if _, aok := faceAuthedMap[cookie.Value]; !aok {
		return Event{
			ID:    cookie.Value,
			Event: FaceValid,
		}
	}

	//TODO cookie 过期
	//if cookie.Expires.Before(time.Now()) {
	//	return NeedReValid
	//}
	//if cookie.Value == DefaultWafHeaderValue {
	//
	//}
	return Event{Event: Pass}
}

func eventHandler(e Event, w http.ResponseWriter, req *http.Request) {
	switch e.Event {
	case NeedFaceValid:
		// set cookie
		c := &http.Cookie{
			Name:     WafHeaderKey,
			Value:    e.ID,
			Path:     "/",
			Domain:   "test-waf.com",
			Expires:  time.Now().Add(time.Hour),
			Secure:   false,
			HttpOnly: false,
			SameSite: 0,
		}
		authedMap[e.ID] = struct{}{}
		w.Header().Add("Set-Cookie", c.String())
		w.Header().Set("Location", "http://test-waf.com/face_auth")
		w.WriteHeader(http.StatusFound)
	case Pass:
		w.WriteHeader(http.StatusOK)
	case FaceValid:
		// mock face auth success
		faceAuthedMap[e.ID] = struct{}{}
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func auth(w http.ResponseWriter, r *http.Request) {
	e := EmitEvent(r)
	eventHandler(e, w, r)
}

func faceAuth(w http.ResponseWriter, r *http.Request) {
	e := EmitEvent(r)
	eventHandler(e, w, r)
}

func main() {
	// 注册处理函数
	http.HandleFunc("/auth", auth)
	http.HandleFunc("/face_auth", faceAuth)

	// 启动服务器，监听在 80 端口
	log.Fatal(http.ListenAndServe(":80", nil))
}
