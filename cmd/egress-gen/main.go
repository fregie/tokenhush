// Command egress-gen regenerates every egress disclosure from the single
// machine-readable manifest (egress.yaml). With -check it verifies the
// committed artifacts instead of writing them, which is how CI guards against a
// hand-edited disclosure or a manifest that was changed without regenerating.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/fregie/tokenhush/internal/egressgen"
)

func main() {
	coreRoot := flag.String("core-root", ".", "核心仓库根（含 egress.yaml）")
	proRoot := flag.String("pro-root", "", "Pro 仓库根；非空时生成 Pro 文档片段")
	webRoot := flag.String("web-root", "", "官网 web 目录；非空时生成官网数据文件")
	manifestPath := flag.String("manifest", "", "清单路径（默认 <core-root>/egress.yaml）")
	check := flag.Bool("check", false, "只校验生成物是否与清单一致，不写盘")
	flag.Parse()

	err := egressgen.Run(egressgen.Options{
		ManifestPath: *manifestPath,
		CoreRoot:     *coreRoot,
		ProRoot:      *proRoot,
		WebRoot:      *webRoot,
		Check:        *check,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "egress-gen: %v\n", err)
		os.Exit(1)
	}
}
