{{- define "vexviper.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "vexviper.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vexviper.labels" -}}
app.kubernetes.io/name: {{ include "vexviper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "vexviper.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vexviper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vexviper.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "vexviper.secretName" -}}
{{- default (include "vexviper.fullname" .) .Values.bomhort.existingSecret -}}
{{- end -}}

{{/* Shared container env */}}
{{- define "vexviper.env" -}}
- name: VEXVIPER_BOMHORT_URL
  value: {{ .Values.bomhort.url | quote }}
- name: VEXVIPER_VEX_UPLOAD
  value: {{ .Values.upload | quote }}
{{- if .Values.git.enabled }}
- name: VEXVIPER_VEX_GIT_ENABLED
  value: "true"
- name: VEXVIPER_VEX_GIT_REPO
  value: {{ required "git.repo is required when git.enabled" .Values.git.repo | quote }}
- name: VEXVIPER_VEX_GIT_BRANCH
  value: {{ .Values.git.branch | quote }}
- name: VEXVIPER_VEX_GIT_PATH
  value: {{ .Values.git.path | quote }}
- name: VEXVIPER_VEX_GIT_BRANCH_PREFIX
  value: {{ .Values.git.branchPrefix | quote }}
- name: VEXVIPER_VEX_GIT_PR
  value: {{ .Values.git.pr | quote }}
- name: VEXVIPER_VEX_GIT_SIGN_OFF
  value: {{ .Values.git.signOff | quote }}
{{- with .Values.git.apiUrl }}
- name: VEXVIPER_VEX_GIT_API_URL
  value: {{ . | quote }}
{{- end }}
{{- end }}
- name: BOMHORT_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "vexviper.secretName" . }}
      key: api-key
      optional: true
- name: OPENAI_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "vexviper.secretName" . }}
      key: openai-api-key
      optional: true
- name: GITHUB_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "vexviper.secretName" . }}
      key: github-token
      optional: true
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Shared pod spec pieces */}}
{{- define "vexviper.volumes" -}}
- name: config
  configMap:
    name: {{ include "vexviper.fullname" . }}
- name: work
{{- if .Values.persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ default (include "vexviper.fullname" .) .Values.persistence.existingClaim }}
{{- else }}
  emptyDir: {}
{{- end }}
{{- end -}}

{{- define "vexviper.volumeMounts" -}}
- name: config
  mountPath: /etc/vexviper
  readOnly: true
- name: work
  mountPath: /work
{{- end -}}
