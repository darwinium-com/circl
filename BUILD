load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("@bazel_gazelle//:def.bzl", "gazelle")

# gazelle:prefix github.com/cloudflare/circl
gazelle(name = "gazelle")

go_library(
    name = "circl",
    srcs = ["doc.go"],
    importpath = "github.com/cloudflare/circl",
    visibility = ["//visibility:public"],
)
