package main

import (
    "flag"
    "fmt"
    "os"
    "strconv"

    "github.com/cilium/ebpf"
)

func main() {
    // 解析命令行参数
    lossRateStr := flag.String("loss-rate", "", "packet loss rate")
    flag.Parse()

    // 检查丢包率参数
    if *lossRateStr == "" {
        fmt.Println("Error: missing loss rate parameter")
        os.Exit(1)
    }

    lossRate, err := strconv.Atoi(*lossRateStr)
    if err != nil {
        fmt.Println("Error: invalid loss rate")
        os.Exit(1)
    }

    // 加载eBPF程序
    obj := new(ebpf.Program)
    err = obj.Load("path/to/your/ebpf/program.o")
    if err != nil {
        fmt.Printf("Error loading eBPF program: %v\n", err)
        os.Exit(1)
    }

    // 获取eBPF映射
    m, err := ebpf.LoadPinnedMap("path/to/your/ebpf/map")
    if err != nil {
        fmt.Printf("Error loading eBPF map: %v\n", err)
        os.Exit(1)
    }

    // 更新eBPF映射中的丢包率
    err = m.Update(ebpf.MapUpdate{
        Key:   0, // 如果您的映射是一个数组映射，可能需要调整此处的键
        Value: lossRate,
    })
    if err != nil {
        fmt.Printf("Error updating eBPF map: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Successfully set loss rate to %d%%\n", lossRate)
}

