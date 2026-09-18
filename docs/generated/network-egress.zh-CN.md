# 网络出口披露

**中文** | [English](network-egress.md)

> 本文件由仓库根目录的 `egress.yaml` 生成，它是厂商绑定出口的唯一事实来源。
> `tokenhush privacy` 渲染同一份数据，`tokenhush privacy --json` 将其输出为 JSON。
> 请勿手工编辑本文件；编辑 `egress.yaml` 后重新生成。

Tokenhush 恰好可以发出两个厂商绑定请求。两者都是命令限定的，意思是只有对应命令运行时才会发出，而且两者都可开关。

| 类别 | 开关（设为 `1` 即关闭） | 主机 | 保留 |
|---|---|---|---|
| `update-check` | `TOKENHUSH_NO_UPDATE_CHECK` | `updates.tokenhush.com` | 厂商访问日志与请求记录保留 30 天。 |
| `rule-sync` | `TOKENHUSH_NO_RULE_SYNC` | `updates.tokenhush.com` | 厂商访问日志与请求记录保留 30 天。 |

这些是 Tokenhush 自身唯一可以发出的厂商绑定请求；两者都是命令限定的且可开关，除此之外，离开这台机器的流量只有用户自己发往其厂商的请求。
