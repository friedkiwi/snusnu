package server

func init() { pages["managed_cp"] = managedCPTemplate }

const nodeAddressTemplate = `{{define "node_address"}}{{if .ManagedMAC}}<code>{{.ManagedMAC}}</code> / SAP <code>04</code><br>{{end}}{{if eq .Kind "CP"}}{{if .ManagedMAC}}<small>ADPTADR <code>{{.ADPTADR}}</code></small>{{else}}Address pending{{end}}{{else}}{{if .HostingCPName}}<small>Hosted by <code>{{.HostingCPNetID}}.{{.HostingCPName}}</code></small>{{else}}Hosting CP unknown{{end}}{{end}}{{end}}`

const managedCPTemplate = `{{define "content"}}
<h1>Automatic LLC address allocations</h1>
<p>Read-only operational view. The concentrator assigns a stable virtual MAC when a control point is first advertised. Users and routers cannot select or retire addresses.</p>
<div class="table-responsive"><table class="table table-striped"><thead><tr><th>Control point</th><th>Owner</th><th>Virtual MAC</th><th>OS/400 ADPTADR</th><th>State</th><th>Advertising routers</th></tr></thead><tbody>
{{range .Items}}<tr><td><code>{{.NetID}}.{{.CPName}}</code></td><td><a href="/profiles/{{.OwnerID}}">View owner</a></td><td><code>{{.MACColon}}</code></td><td><code>{{.ADPTADR}}</code></td><td>{{if .Online}}Online{{else}}Offline{{end}}</td><td>{{range .Advertisers}}{{.}}<br>{{else}}—{{end}}</td></tr>{{else}}<tr><td colspan="6">No automatic allocations.</td></tr>{{end}}
</tbody></table></div><p class="text-muted">Allocations remain reserved across route withdrawal and reconnects so local LLC configuration stays stable.</p>{{end}}`
