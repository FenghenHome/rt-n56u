THISDIR = $(shell pwd)
xray_dir="xray-core/core/main"
export GO111MODULE=on
export GOPROXY=https://goproxy.cn
Xray_VERSION := 1.4.0
Xray_URL := https://codeload.github.com/XTLS/Xray-core/tar.gz/v$(Xray_VERSION)
XRAY_SED_ARGS:=
XRAY_SED_ARGS += \
	s/_ "xray-core\/core\/main\/json"/\/\/ &/; \
	/\/\/ _ "xray-core\/core\/main\/jsonem"/s/\/\/ //;
XRAY_SED_ARGS += \
	s/_ "xray-core\/core\/main\/json"/\/\/ &/;

all:download_x build_extract build_xray

download_x:
	( if [ ! -f $(THISDIR)/Xray-core-$(Xray_VERSION).tar.gz ]; then \
	curl --create-dirs -L $(Xray_URL) -o $(THISDIR)/Xray-core-$(Xray_VERSION).tar.gz ; \
	fi )

build_extract:
	mkdir -p $(THISDIR)/xray-core
	mkdir -p $(THISDIR)/bin
	( if [ ! -d $(THISDIR)/xray-core/core ]; then \
	tar zxfv $(THISDIR)/Xray-core-$(Xray_VERSION).tar.gz -C $(THISDIR)/xray-core ; \
	mv $(THISDIR)/xray-core/Xray-core-$(Xray_VERSION) $(THISDIR)/xray-core/core ; \
	fi )

build_xray:
	( cd $(THISDIR)/$(xray_dir); \
	sed -i \
			'$(XRAY_SED_ARGS)' \
			distro/all/all.go ; \
	GOOS=linux GOARCH=mipsle go build -ldflags "-w -s" -o $(THISDIR)/bin/xray; \
	$(ROOTDIR)/tools/upx/upx --lzma --best $(THISDIR)/bin/xray -o $(THISDIR)/bin/xray-upx; \
	)

clean:
	rm -rf $(THISDIR)/xray-core
	rm -rf $(THISDIR)/bin

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/bin/xray-upx /usr/bin/xray
