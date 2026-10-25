$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'kind-quota.ps1')
$valid='{"metadata":{"name":"themis-test-budget","namespace":"themis-test","uid":"original-quota"},"spec":{"hard":{"count/verificationruns.verification.themis.dev":"32","count/deployments.apps":"4","pods":"8","configmaps":"8","secrets":"8"}},"status":{"hard":{"count/verificationruns.verification.themis.dev":"32","count/deployments.apps":"4","pods":"8","configmaps":"8","secrets":"8"},"used":{"count/verificationruns.verification.themis.dev":"0","count/deployments.apps":"1","pods":"1","configmaps":"1","secrets":"0"}}}'
foreach($mode in @('ready','missing-custom-used','pod-only','wrong-hard','wrong-spec','negative-used','excess-used','wrong-namespace','missing-uid')){
    $q=$valid|ConvertFrom-Json
    switch($mode){
        'missing-custom-used' {$q.status.used.PSObject.Properties.Remove('count/verificationruns.verification.themis.dev')}
        'pod-only' {$q.status.hard.PSObject.Properties.Remove('count/verificationruns.verification.themis.dev')}
        'wrong-hard' {$q.status.hard.'count/verificationruns.verification.themis.dev'='64'}
        'wrong-spec' {$q.spec.hard.'count/verificationruns.verification.themis.dev'='64'}
        'negative-used' {$q.status.used.'count/verificationruns.verification.themis.dev'='-1'}
        'excess-used' {$q.status.used.'count/verificationruns.verification.themis.dev'='33'}
        'wrong-namespace' {$q.metadata.namespace='other'}
        'missing-uid' {$q.metadata.uid=$null}
    }
    $actual=Test-ThemisVerificationQuota $q
    if($actual -ne ($mode -eq 'ready')){throw "Incorrect quota readiness: $mode"}
    Write-Output "$mode : expected readiness $actual"
}
# A replaced quota must abort before any subsequent readiness can authorize use.
$script:calls=0
function Invoke-ThemisKubectl($Arguments){
    $script:calls++
    $q=$valid|ConvertFrom-Json
    if($script:calls -eq 1){$q.status.used.PSObject.Properties.Remove('count/verificationruns.verification.themis.dev')}else{$q.metadata.uid='replacement-quota'}
    return ($q|ConvertTo-Json -Depth 8)
}
$denied=$false
try{Wait-ThemisVerificationQuota}catch{if($_.Exception.Message -eq 'Original quota replaced; no request permitted'){$denied=$true}else{throw}}
if(-not $denied -or $script:calls -ne 2){throw 'Replaced quota was accepted'}
Write-Output 'replaced-quota : denied'
