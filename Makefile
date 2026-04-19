TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = roothide

DEBUG ?= 0
FINALPACKAGE ?= 1

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = lockdown2

lockdown2_FILES = Tweak.x
lockdown2_CFLAGS = -I./ -fobjc-arc -Wno-unused-function -Wno-unused-variable
lockdown2_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk


before-all::
	rm -rf ./packages
