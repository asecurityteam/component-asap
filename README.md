<a id="markdown-component-asap---settings-component-for-generating-on-demand-asap-tokens" name="component-asap---settings-component-for-generating-on-demand-asap-tokens"></a>
# component-asap - Settings component for generating on demand ASAP tokens

<a id="markdown-overview" name="overview"></a>
## Overview

This is a [`settings`](https://github.com/asecurityteam/settings) that enables
constructing a `RoundTripper` that inject an ASAP token into the outgoing request.

<a id="markdown-quick-start" name="quick-start"></a>
## Quick Start
```golang
package main

import (
    "context"
    "net/http"

    accesslog "github.com/asecurityteam/component-accesslog"
)

func main() {
    ctx := context.Background()
	accessLogComponent := AccessLogComponent{}
    accessLogConfig := accessLogComponent.Settings()
    wrapper, _ := accessLogComponent.New(ctx, accessLogConfig)
    transport := wrapper(http.DefaultTransport)
    client := &http.Client{Transport: transport}
    req, _ := http.NewRequest(http.MethodGet, "www.google.com", http.NoBody)

    // should see accesslogs
    _, _ := j.HTTPClient.Do(req)

}
```

<a id="markdown-license" name="license"></a>
### License

This project is licensed under Apache 2.0. See LICENSE.txt for details.

<a id="markdown-contributing-agreement" name="contributing-agreement"></a>
### Contributing Agreement

Atlassian requires signing a contributor's agreement before we can accept a patch. If
you are an individual you can fill out the [individual
CLA](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d).
If you are contributing on behalf of your company then please fill out the [corporate
CLA](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=e1c17c66-ca4d-4aab-a953-2c231af4a20b).