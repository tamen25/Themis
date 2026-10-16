param([string]$CommandProxy='')
. (Join-Path $PSScriptRoot 'kind-common.ps1') -CommandProxy $CommandProxy
$owner=Assert-ThemisCluster
Invoke-ThemisTool $script:ThemisKind @('delete','cluster','--name',$owner.clusterName)
# Keep private ownership/config records for diagnosis. Remove them manually
# before a fresh setup after confirming the exact directory and cluster absence.
Write-Output 'Owned themis-t20 cluster deleted; no other Kind cluster was selected.'
