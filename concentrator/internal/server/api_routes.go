package server

import (
	"net/http"
	"reflect"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

type apiEndpoint struct {
	Method, Path, OperationID, Summary string
	ResponseModel                      any
	Handler                            func(http.ResponseWriter, *http.Request, store.User)
	Searchable                         bool
}

// apiEndpoints is the single source of truth for both API registration and
// the generated OpenAPI document.
func (a *App) apiEndpoints() []apiEndpoint {
	return []apiEndpoint{
		{Method: http.MethodGet, Path: "/api/v1/directory", OperationID: "listDirectory", Summary: "List live global SNA directory entries", ResponseModel: store.Export{}, Handler: a.apiDirectory},
		{Method: http.MethodGet, Path: "/api/v1/connections", OperationID: "listConnections", Summary: "List planning connections visible to the API-key owner", ResponseModel: Connection{}, Handler: a.apiConnections},
		{Method: http.MethodGet, Path: "/api/v1/flows", OperationID: "listFlows", Summary: "List flows visible to the API-key owner", ResponseModel: store.LogEntry{}, Handler: a.apiFlows, Searchable: true},
	}
}

func (a *App) apiFlows(w http.ResponseWriter, r *http.Request, u store.User) {
	ownerID := u.ID
	if u.Role == "admin" {
		ownerID = ""
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	items, err := a.DB.SearchFlows(r.Context(), ownerID, q)
	if err != nil {
		dbError(w, err)
		return
	}
	jsonResponse(w, items)
}

func (a *App) openAPISpec(w http.ResponseWriter, r *http.Request) {
	paths := map[string]any{}
	schemas := map[string]any{}
	for _, endpoint := range a.apiEndpoints() {
		modelType := reflect.TypeOf(endpoint.ResponseModel)
		schemas[modelType.Name()] = schemaForType(modelType)
		operation := map[string]any{
			"operationId": endpoint.OperationID,
			"summary":     endpoint.Summary,
			"security":    []any{map[string]any{"bearerAuth": []string{}}},
			"responses": map[string]any{
				"200": map[string]any{"description": "Successful response", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/" + modelType.Name()}}}}},
				"401": map[string]any{"description": "Missing, invalid or revoked API key"},
			},
		}
		if endpoint.Searchable {
			operation["parameters"] = []any{map[string]any{"name": "q", "in": "query", "required": false, "description": "Case-insensitive search across flow fields", "schema": map[string]any{"type": "string", "maxLength": 100}}}
		}
		paths[endpoint.Path] = map[string]any{strings.ToLower(endpoint.Method): operation}
	}
	spec := map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]any{"title": "snusnu user API", "version": "1.0.0", "description": "Read-only API. Every bearer key inherits the current permissions of its owning user."},
		"paths":   paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "snusnu API key"}},
			"schemas":         schemas,
		},
	}
	jsonResponse(w, spec)
}

func schemaForType(t reflect.Type) map[string]any {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		properties := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			name := field.Name
			if tag := strings.Split(field.Tag.Get("json"), ",")[0]; tag != "" {
				if tag == "-" {
					continue
				}
				name = tag
			}
			properties[name] = schemaForType(field.Type)
		}
		return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaForType(t.Elem())}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer", "format": "int64"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	default:
		return map[string]any{"type": "string"}
	}
}
