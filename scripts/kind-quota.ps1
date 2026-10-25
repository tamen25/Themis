# Only installer-side readiness; the API server remains the quota authority.
function Test-ThemisVerificationQuota($Quota) {
    if($Quota.metadata.name -ne 'themis-test-budget' -or $Quota.metadata.namespace -ne 'themis-test' -or -not $Quota.metadata.uid){return $false}
    $expected=@{'count/verificationruns.verification.themis.dev'='32';'count/deployments.apps'='4';pods='8';configmaps='8';secrets='8'}
    foreach($key in $expected.Keys){
        if([string]$Quota.spec.hard.$key -cne $expected[$key] -or [string]$Quota.status.hard.$key -cne $expected[$key]){return $false}
        $used=[string]$Quota.status.used.$key
        if($used -notmatch '^(0|[1-9][0-9]*)$' -or [decimal]$used -gt [decimal]$expected[$key]){return $false}
    }
    return $true
}

function Wait-ThemisVerificationQuota {
    # Kubernetes v1.35.5 discovers new quota evaluators every 30s but periodically
    # recalculates existing quotas every 5m. A newly installed CRD may need that
    # first recalculation to populate status.used. The measured first use was
    # about 5m; allow one full cycle plus 1m, then fail without creating a run.
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $originalUID=$null
    while($watch.Elapsed.TotalSeconds -lt 360){
        $quota=(Invoke-ThemisKubectl @('--request-timeout=10s','get','resourcequota','themis-test-budget','-n','themis-test','-o','json'))-join "`n"|ConvertFrom-Json
        if(-not $quota.metadata.uid){throw 'Quota UID missing; no request permitted'}
        if(-not $originalUID){$originalUID=$quota.metadata.uid}
        if($quota.metadata.uid -ne $originalUID){throw 'Original quota replaced; no request permitted'}
        if(Test-ThemisVerificationQuota $quota){return}
        Start-Sleep -Milliseconds 300
    }
    throw 'VerificationRun quota initialization timed out; no request permitted'
}
