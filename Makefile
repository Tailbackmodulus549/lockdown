TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = roothide

DEBUG ?= 0
FINALPACKAGE ?= 1

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = lockdown

lockdown_FILES = Tweak.x
lockdown_CFLAGS = -I./ -fobjc-arc -Wno-unused-function -Wno-unused-variable
lockdown_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk


before-all::
	rm -rf ./packages
