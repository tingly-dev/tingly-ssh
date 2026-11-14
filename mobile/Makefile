.PHONY: android ios test

ANDROID_API ?= 24
IOS_VERSION ?= 12.0
JAVAPKG ?= dev.tingly.ssh
OUT ?= ../dist/mobile
ANDROID_NDK_HOME ?= $(HOME)/Library/Android/sdk/ndk/29.0.14206865

PKG := github.com/tingly-dev/tingly-ssh/mobile

android:
	@mkdir -p $(OUT)
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) gomobile bind -target=android -androidapi=$(ANDROID_API) \
		-javapkg=$(JAVAPKG) -o $(OUT)/tingly-ssh.aar $(PKG)

ios:
	@mkdir -p $(OUT)
	gomobile bind -target=ios,iossimulator -iosversion=$(IOS_VERSION) \
		-o $(OUT)/TinglySSH.xcframework $(PKG)

test:
	go test ./...
