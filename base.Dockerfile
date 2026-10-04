# openppp2 基础镜像：ubuntu 22.04 + 全部运行时依赖
# 作为增量构建的 BASE_IMAGE，避免每次重装依赖
# 22.04（glibc 2.35）：与 CI 编译环境一致，二进制可跑 Debian 11+/Ubuntu 20.04+
FROM ubuntu:22.04

# 环境变量（与 entrypoint.sh 配合）
ENV ENABLE_IO=false
ENV ENABLE_SIMD=false
ENV ENABLE_TC=false
ENV ENABLE_BYPASS=false
ENV BYPASS_COUNTRY=CN
ENV BYPASS_IPLIST_PATH=/opt/ip.txt
ENV BYPASS_REFRESH=true
ENV BYPASS_PULL_ON_START=true

# 安装运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    iptables \
    iproute2 \
    iputils-ping \
    libatomic1 \
    liburing2 \
    libbpf0 \
    libunwind8 \
    lsof \
    net-tools && \
    rm -rf /var/lib/apt/lists/*

# 工作目录
WORKDIR /opt

# 启动脚本（构建时由 ppp.Dockerfile COPY 覆盖，这里先放默认占位）
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
