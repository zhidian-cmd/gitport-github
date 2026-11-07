# Architecture overview

GitPort GitHub is a Windows desktop application that runs a loopback proxy and a local management UI. The diagram below shows the main runtime components and how configuration and traffic flow between them.

```mermaid
flowchart LR
    subgraph Client[Client applications]
        Browser[Browser]
        Git[Git and other CLI tools]
    end

    subgraph Windows[Windows host]
        SystemProxy[System proxy / PAC settings]
        subgraph GitPort[GitPort GitHub process]
            Desktop[Desktop shell and tray]
            Proxy[Loopback proxy server\n127.0.0.1:7810]
            WebUI[Management UI and API\n127.0.0.1:7811]
            Classifier[Request classification]
            Routes[Route configuration\n(routes.json)]
            Settings[Application settings]
            Pool[Upstream connection pool]
            MITM[Optional managed-host TLS inspection]
            Logs[Runtime logs and status]
        end
        LocalCA[Optional local certificate authority]
    end

    subgraph Upstreams[Remote services]
        GitHub[GitHub and GitHub content endpoints]
        Mirrors[User-configured content mirrors\n(eligible requests only)]
    end

    Browser --> SystemProxy
    Git --> SystemProxy
    SystemProxy -->|GitHub traffic routed locally| Proxy
    SystemProxy -->|Other traffic remains direct| Other[Other websites]

    Proxy --> Classifier
    Classifier -->|Tunnel / streaming path| Pool
    Classifier -->|Optional inspection enabled| MITM
    MITM --> Pool
    MITM -. certificate issuance when needed .-> LocalCA
    Pool -->|Route and connection selection| Routes
    Pool --> GitHub
    Pool -->|Eligible content fallback| Mirrors
    GitHub --> Pool
    Mirrors --> Pool
    Pool --> Proxy
    Proxy --> Client

    Desktop --> WebUI
    WebUI --> Settings
    WebUI --> Routes
    WebUI --> Logs
    Proxy --> Logs
    WebUI -. controls proxy integration .-> SystemProxy
```

## Component responsibilities

- **System proxy integration** directs selected GitHub traffic to the loopback proxy; unrelated traffic is not handled by GitPort. The application restores proxy settings when it exits.
- **Loopback proxy** accepts client requests and selects a tunnel, streaming, or managed inspection path according to the request and current settings.
- **Routing and connection pool** use the local route configuration to select upstream connections and, where configured and appropriate, a content mirror fallback.
- **Management UI and desktop shell** expose configuration, status, logs, and desktop/tray controls.
- **Optional TLS inspection** is disabled unless enabled by the user. The local certificate authority is used for managed GitHub-related hosts only.
- **Configuration and logs** are local application state. Mirror use is configurable; requests containing signed download credentials are not sent to untrusted mirrors by default.

See [工作原理](ARCHITECTURE.md) for detailed request flows and routing behavior, and [高级配置](CONFIG.md) for configuration details.
