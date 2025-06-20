#!/bin/bash

# CodeVigil 快速启动脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的信息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查Docker是否安装
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker 未安装，请先安装 Docker"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose 未安装，请先安装 Docker Compose"
        exit 1
    fi
}

# 检查环境变量
check_env() {
    if [ ! -f .env ]; then
        print_warning ".env 文件不存在，将从 .env.example 创建"
        if [ -f .env.example ]; then
            cp .env.example .env
            print_info "请编辑 .env 文件配置必要的环境变量"
        else
            print_error ".env.example 文件不存在"
            exit 1
        fi
    fi
}

# 显示帮助信息
show_help() {
    echo "CodeVigil 快速启动脚本"
    echo ""
    echo "用法:"
    echo "  $0 [命令] [选项]"
    echo ""
    echo "命令:"
    echo "  dev     启动开发环境"
    echo "  prod    启动生产环境"
    echo "  stop    停止所有服务"
    echo "  restart 重启所有服务"
    echo "  logs    查看服务日志"
    echo "  clean   清理所有容器和卷"
    echo "  build   重新构建镜像"
    echo "  status  查看服务状态"
    echo "  help    显示此帮助信息"
    echo ""
    echo "选项:"
    echo "  --no-cache    构建时不使用缓存"
    echo "  --pull        构建前拉取最新基础镜像"
    echo ""
}

# 启动开发环境
start_dev() {
    print_info "启动开发环境..."
    docker-compose -f docker-compose.dev.yml up -d
    print_success "开发环境启动完成"
    echo ""
    echo "服务访问地址:"
    echo "  前端: http://localhost:3000"
    echo "  后端: http://localhost:8000"
    echo "  数据库管理: http://localhost:8080"
    echo ""
    echo "查看日志: $0 logs"
}

# 启动生产环境
start_prod() {
    print_info "启动生产环境..."
    docker-compose up -d
    print_success "生产环境启动完成"
    echo ""
    echo "服务访问地址:"
    echo "  应用: http://localhost:3000"
    echo "  API: http://localhost:8000"
    echo ""
}

# 停止服务
stop_services() {
    print_info "停止所有服务..."
    docker-compose -f docker-compose.dev.yml down 2>/dev/null || true
    docker-compose down 2>/dev/null || true
    print_success "所有服务已停止"
}

# 重启服务
restart_services() {
    print_info "重启服务..."
    stop_services
    if [ "$1" = "dev" ]; then
        start_dev
    else
        start_prod
    fi
}

# 查看日志
show_logs() {
    if docker-compose -f docker-compose.dev.yml ps -q &>/dev/null; then
        docker-compose -f docker-compose.dev.yml logs -f
    else
        docker-compose logs -f
    fi
}

# 清理环境
clean_env() {
    print_warning "这将删除所有容器、镜像和数据卷，确定继续吗? (y/N)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        print_info "清理环境..."
        docker-compose -f docker-compose.dev.yml down -v --rmi all 2>/dev/null || true
        docker-compose down -v --rmi all 2>/dev/null || true
        docker system prune -f
        print_success "环境清理完成"
    else
        print_info "清理操作已取消"
    fi
}

# 构建镜像
build_images() {
    local args=""
    if [[ "$*" =~ --no-cache ]]; then
        args="$args --no-cache"
    fi
    if [[ "$*" =~ --pull ]]; then
        args="$args --pull"
    fi
    
    print_info "构建镜像..."
    docker-compose build $args
    print_success "镜像构建完成"
}

# 查看状态
show_status() {
    print_info "服务状态:"
    echo ""
    if docker-compose -f docker-compose.dev.yml ps 2>/dev/null | grep -q "Up"; then
        echo "开发环境状态:"
        docker-compose -f docker-compose.dev.yml ps
    elif docker-compose ps 2>/dev/null | grep -q "Up"; then
        echo "生产环境状态:"
        docker-compose ps
    else
        print_warning "没有运行中的服务"
    fi
}

# 主函数
main() {
    # 检查依赖
    check_docker
    check_env
    
    case "$1" in
        "dev")
            start_dev
            ;;
        "prod")
            start_prod
            ;;
        "stop")
            stop_services
            ;;
        "restart")
            restart_services "$2"
            ;;
        "logs")
            show_logs
            ;;
        "clean")
            clean_env
            ;;
        "build")
            build_images "$@"
            ;;
        "status")
            show_status
            ;;
        "help"|"")
            show_help
            ;;
        *)
            print_error "未知命令: $1"
            show_help
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"
