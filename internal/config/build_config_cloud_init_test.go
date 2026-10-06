package config

import "testing"

func TestBuildConfigCloudInitDefaultsOff(t *testing.T) {
	var b BuildConfig
	if b.IsCloudInitEnabled() {
		t.Error("cloud_init must default to false")
	}
	on := true
	b.CloudInit = &on
	if !b.IsCloudInitEnabled() {
		t.Error("cloud_init = true must enable it")
	}
}

// A profile/project layer can turn it on, and an unset layer leaves it alone.
func TestMergeBuildCloudInit(t *testing.T) {
	on, off := true, false
	dst := BuildConfig{CloudInit: &off}
	mergeBuildInto(&dst, &BuildConfig{})
	if dst.IsCloudInitEnabled() || dst.CloudInit == nil {
		t.Error("an unset layer must not change cloud_init")
	}
	mergeBuildInto(&dst, &BuildConfig{CloudInit: &on})
	if !dst.IsCloudInitEnabled() {
		t.Error("a layer setting cloud_init = true must win")
	}
}
