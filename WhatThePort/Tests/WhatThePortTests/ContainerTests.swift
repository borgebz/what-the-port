import Foundation
import Testing
@testable import WhatThePort

struct ContainerTests {
    @Test func runtimesAreRecognisedByTheirAppBundle() {
        #expect(ContainerRuntime.owning(executablePath: "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper") == .orbStack)
        #expect(ContainerRuntime.owning(executablePath: "/Applications/Docker.app/Contents/MacOS/com.docker.backend") == .docker)
        #expect(ContainerRuntime.owning(executablePath: "/opt/homebrew/bin/node") == nil)
    }

    @Test func containerListKeepsPublishedTCPPortsAndComposeLabels() {
        let json: [String: Any] = [
            "Id": "25dff7df533f0123",
            "Names": ["/shop-db-1"],
            "Image": "postgres:16-alpine",
            "Ports": [
                ["IP": "0.0.0.0", "PrivatePort": 5432, "PublicPort": 5433, "Type": "tcp"],
                ["IP": "::", "PrivatePort": 5432, "PublicPort": 5433, "Type": "tcp"],
                ["PrivatePort": 9000, "Type": "tcp"],
                ["IP": "0.0.0.0", "PrivatePort": 53, "PublicPort": 5353, "Type": "udp"],
            ],
            "Labels": [
                "com.docker.compose.project": "shop",
                "com.docker.compose.service": "db",
                "com.docker.compose.project.working_dir": "/Users/me/shop",
            ],
        ]
        let container = DockerEngine.parseContainer(json, runtime: .orbStack)
        #expect(container?.name == "shop-db-1")
        #expect(container?.publishedPorts == [5433])
        #expect(container?.composeService == "db")
        #expect(container?.workingDirectory == "/Users/me/shop")
        #expect(container?.shortID == "25dff7df533f")

        var unpublished = json
        unpublished["Ports"] = [["PrivatePort": 5432, "Type": "tcp"]]
        #expect(DockerEngine.parseContainer(unpublished, runtime: .orbStack) == nil)
    }

    @Test func memoryExcludesReclaimablePageCacheLikeDockerStats() {
        let cgroupV2: [String: Any] = [
            "memory_stats": ["usage": 1_339_572_224, "stats": ["inactive_file": 7_897_088]],
            "cpu_stats": ["cpu_usage": ["total_usage": 43_018_077_000]],
        ]
        #expect(DockerEngine.parseUsage(cgroupV2) == ContainerUsage(memory: 1_331_675_136, cpuNanoseconds: 43_018_077_000))
        let cgroupV1: [String: Any] = [
            "memory_stats": ["usage": 1000, "stats": ["total_inactive_file": 200]],
            "cpu_stats": ["cpu_usage": ["total_usage": 5]],
        ]
        #expect(DockerEngine.parseUsage(cgroupV1)?.memory == 800)
        #expect(DockerEngine.parseUsage(["memory_stats": [:], "cpu_stats": [:]]) == nil)
    }

    @Test func responsesAreReadWithAndWithoutChunking() {
        let plain = Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]".utf8)
        #expect(DockerEngine.parseResponse(plain) == Data("[]".utf8))
        let chunked = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n[{\"a\r\n4\r\n\":1}\r\n1\r\n]\r\n0\r\n\r\n".utf8)
        #expect(DockerEngine.parseResponse(chunked) == Data("[{\"a\":1}]".utf8))
        let stopped = Data("HTTP/1.1 304 Not Modified\r\n\r\n".utf8)
        #expect(DockerEngine.parseResponse(stopped) == nil)
        let missing = Data("HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}".utf8)
        #expect(DockerEngine.parseResponse(missing) == nil)
    }

    @Test func imagesMatchTheProtectedProcessNames() {
        func container(_ image: String) -> ContainerInfo {
            ContainerInfo(id: "id", name: "n", image: image, runtime: .docker, publishedPorts: [1])
        }
        let protected = Set(Preferences.defaultProtected)
        #expect(container("postgres:16").isProtected(by: protected))
        #expect(container("redis:7-alpine").isProtected(by: protected))
        #expect(container("mongo:7").isProtected(by: protected))
        #expect(container("mysql:8").isProtected(by: protected))
        #expect(container("docker.io/library/postgres@sha256:abc").isProtected(by: protected))
        #expect(!container("ghcr.io/saleor/saleor:3.22").isProtected(by: protected))
        #expect(container("ghcr.io/saleor/saleor:3.22").imageName == "saleor")
        #expect(container("localhost:5000/team/api:dev").imageName == "api")
    }
}
