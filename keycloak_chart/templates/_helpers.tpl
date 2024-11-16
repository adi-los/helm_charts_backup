{{- define "keycloak.fullname" -}}
{{- printf "%s-%s" .Release.Name "keycloak" | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "postgres.fullname" -}}
{{- printf "%s-%s" .Release.Name "postgres" | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "rabbitmq.fullname" -}}
{{- printf "%s-%s" .Release.Name "rabbitmq" | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "keycloak.labels" -}}
helm.sh/chart: {{ include "keycloak.chart" . }}
{{ include "keycloak.selectorLabels" . }}
{{- end }}

{{- define "keycloak.selectorLabels" -}}
app.kubernetes.io/name: keycloak
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "postgres.labels" -}}
helm.sh/chart: {{ include "postgres.chart" . }}
{{ include "postgres.selectorLabels" . }}
{{- end }}

{{- define "rabbitmq.labels" -}}
helm.sh/chart: {{ include "rabbitmq.chart" . }}
{{ include "rabbitmq.selectorLabels" . }}
{{- end }}
