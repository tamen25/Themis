param([string]$CommandProxy='')
. (Join-Path $PSScriptRoot 'kind-common.ps1') -CommandProxy $CommandProxy
$owner=Assert-ThemisCluster
Push-Location -LiteralPath $script:ThemisRepository
try {
    # Installation creates the test workload. The controller itself has no
    # permission to create/patch Deployments, pods, RBAC, CRDs or policies.
    Invoke-ThemisKubectl @('create','-f','examples/kubernetes/workload.yaml')
    Invoke-ThemisKubectl @('apply','-f','config/crd/verificationruns.yaml')
    Invoke-ThemisKubectl @('wait','--for=condition=Established','crd/verificationruns.verification.themis.dev','--timeout=60s')
    Invoke-ThemisKubectl @('apply','-f','config/kubernetes/admission.yaml')
    Invoke-ThemisKubectl @('apply','-f','config/kubernetes/quota.yaml')
    Invoke-ThemisKubectl @('wait','--for=jsonpath={.status.hard.pods}=8','resourcequota/themis-test-budget','-n','themis-test','--timeout=60s')
    Invoke-ThemisKubectl @('apply','-f','config/kubernetes/rbac.yaml')
    $owner|Add-Member -Force -NotePropertyName namespaceUID -NotePropertyValue (Invoke-ThemisKubectl @('get','namespace','themis-test','-o','jsonpath={.metadata.uid}'))
    $encoding=[Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $script:ThemisState 'ownership.json'),($owner|ConvertTo-Json),$encoding)
    $pins="apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: themis-controller-pins`n  namespace: themis-test`ndata:`n  clusterUID: '$($owner.clusterUID)'`n  namespaceUID: '$($owner.namespaceUID)'`n"
    $pinsPath=Join-Path $script:ThemisState 'controller-pins.yaml'
    [IO.File]::WriteAllText($pinsPath,$pins,$encoding)
    Invoke-ThemisKubectl @('apply','-f',$pinsPath)
    & (Join-Path $PSScriptRoot 'kind-controller.ps1') -CommandProxy $CommandProxy
    Invoke-ThemisKubectl @('rollout','status','deployment/synthetic','-n','themis-test','--timeout=120s')
    $target=(Invoke-ThemisKubectl @('get','deployment','synthetic','-n','themis-test','-o','json'))-join "`n"|ConvertFrom-Json
    $example=[IO.File]::ReadAllText((Join-Path $script:ThemisRepository 'examples/kubernetes/run.yaml')).Replace('REPLACE_WITH_ACTUAL_DEPLOYMENT_UID',$target.metadata.uid)
    $examplePath=Join-Path $script:ThemisState 'run.yaml'
    [IO.File]::WriteAllText($examplePath,$example,$encoding)
    Invoke-ThemisKubectl @('create','-f',$examplePath)
    Write-Output 'Owned Kind test environment installed. No target fault was applied.'
} finally {Pop-Location}
