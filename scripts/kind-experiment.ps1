param(
    [ValidateSet('up','down','restart-controller','test-lifecycle')][string]$Action='up',
    [string]$CommandProxy=''
)
$ErrorActionPreference='Stop'
$repository=Split-Path -Parent $PSScriptRoot
$state=Join-Path $repository '.themis/kind-t21'
$adminConfig=Join-Path $state 'admin-kubeconfig'
$kind=Join-Path $repository '.cache/tools/kind'
$runner=Join-Path $repository '.cache/themis-kube'
if($env:OS -eq 'Windows_NT'){$kind+='.exe';$runner+='.exe'}
$encoding=[Text.UTF8Encoding]::new($false)

function Tool([string]$Program,[string[]]$Arguments){
    $preference=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try {
        if($CommandProxy){$output=& $CommandProxy proxy $Program @Arguments}else{$output=& $Program @Arguments}
        $code=$LASTEXITCODE
    }finally{$ErrorActionPreference=$preference}
    if($code -ne 0){
        # Go test output is public diagnostic evidence. Preserve it on failure;
        # other setup commands may return credentials and stay unprinted.
        if($Program -eq 'go' -and $Arguments[0] -eq 'test'){
            foreach($line in $output){[Console]::Out.WriteLine($line)}
        }
        throw "$Program exited $code"
    }
    return $output
}
function Kube([string[]]$Arguments){Tool 'kubectl' (@('--kubeconfig',$adminConfig,'--context','kind-themis-t21')+$Arguments)}
function Owned {
    $owner=[IO.File]::ReadAllText((Join-Path $state 'bootstrap-owner.json'))|ConvertFrom-Json
    if($owner.clusterName -ne 'themis-t21' -or $owner.context -ne 'kind-themis-t21' -or -not $owner.clusterUID){throw 'Complete owned Kind identity required'}
    $live=Kube @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}')
    if($live -ne $owner.clusterUID){throw 'Cluster UID differs; refusing all mutations'}
    if($owner.namespaceUID){
        $namespace=Kube @('get','namespace','themis-test','-o','jsonpath={.metadata.uid}')
        if($namespace -ne $owner.namespaceUID){throw 'Namespace UID differs; refusing all mutations'}
    }
    return $owner
}
function Mutate([string[]]$Arguments){$null=Owned;Kube $Arguments}
function Protect([string]$Path,[bool]$Directory){
    if($env:OS -eq 'Windows_NT'){
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
        if($Directory){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit='ContainerInherit,ObjectInherit'}else{$acl=[Security.AccessControl.FileSecurity]::new();$inherit='None'}
        $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,'None','Allow'))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }else{if($Directory){$mode='700'}else{$mode='600'};Tool 'chmod' @($mode,$Path)}
}
function PrivateFile([string]$Name,[string]$Content){
    $path=Join-Path $state $Name
    if(Test-Path -LiteralPath $path){throw 'Private setup files are never overwritten'}
    [IO.File]::WriteAllText($path,$Content,$encoding);Protect $path $false
    return $path
}
function SaveOwner($Owner){
    $path=Join-Path $state 'bootstrap-owner.json'
    $exists=Test-Path -LiteralPath $path
    [IO.File]::WriteAllText($path,($Owner|ConvertTo-Json -Depth 5),$encoding)
    # Updating content preserves its existing protected owner-only ACL. Replacing
    # that descriptor is unnecessary and can require unavailable Windows rights.
    if(-not $exists){Protect $path $false}
}

Push-Location -LiteralPath $repository
try {
    if($Action -ne 'up'){
        $owner=Owned
        if($Action -eq 'test-lifecycle'){
            $env:THEMIS_KIND_LIFECYCLE='1'
            $env:THEMIS_KIND_EXPERIMENT_STATE=$state
            $env:THEMIS_KUBE_RUNNER_BINARY=$runner
            $env:THEMIS_TEST_COMMAND_PROXY=$CommandProxy
            Tool 'go' @('build','-trimpath','-o',$runner,'./cmd/themis-kube')
            # Keep these sequential: the live adversarial tests deliberately alter
            # only this owned fixture and temporarily pause this cluster's API task.
            Tool 'go' @('test','-count=1','-v','./internal/kubeexperiment','-run','^TestRealKindJournalWriterTermination$')
            Tool 'go' @('test','-count=1','-v','./test/kubernetesexperiment')
            return
        }
        if($Action -eq 'down'){
            Tool $kind @('delete','cluster','--name','themis-t21')
            Write-Output 'Deleted only the UID-verified owned themis-t21 cluster; private records retained.'
        }else{
            Mutate @('rollout','restart','deployment/themis-controller','-n','themis-test')
            Kube @('rollout','status','deployment/themis-controller','-n','themis-test','--timeout=120s')
        }
        return
    }
    if((Tool $kind @('version')) -notmatch '^kind v0\.32\.0 '){throw 'Pinned Kind v0.32.0 required in .cache/tools'}
    $previous=@(Tool $kind @('get','clusters'))
    if($previous -contains 'themis-t21' -or (Test-Path -LiteralPath $state)){throw 'Requires a new owned cluster and private state; never adopts existing clusters'}
    New-Item -ItemType Directory -Path $state | Out-Null
    Protect $state $true
    $owner=[ordered]@{version='themis.kind-bootstrap/t2.1-v1';clusterName='themis-t21';context='kind-themis-t21';previousClusters=$previous;clusterUID='';namespaceUID=''}
    SaveOwner $owner
    $env:GOCACHE=Join-Path $repository '.cache/go-build'
    $env:GOMODCACHE=Join-Path $repository '.cache/go-mod'
    $env:GOPATH=Join-Path $repository '.cache/go-path'
    $env:GOTMPDIR=Join-Path $repository '.cache/tmp'
    New-Item -ItemType Directory -Force -Path $env:GOCACHE,$env:GOMODCACHE,$env:GOPATH,$env:GOTMPDIR | Out-Null
    Tool 'go' @('build','-trimpath','-o',$runner,'./cmd/themis-kube')
    $approval=(Tool $runner @('init','--state',$state))-join "`n"|ConvertFrom-Json
    Tool $kind @('create','cluster','--name','themis-t21','--config','examples/kubernetes-experiment/kind.yaml','--kubeconfig',$adminConfig,'--wait','120s')
    Protect $adminConfig $false
    $owner.clusterUID=Kube @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}');SaveOwner $owner
    $managerArgs=(Kube @('get','pod','kube-controller-manager-themis-t21-control-plane','-n','kube-system','-o','jsonpath={.spec.containers[0].command}'))-join "`n"|ConvertFrom-Json
    if($managerArgs -notcontains '--resource-quota-sync-period=5s'){throw 'Owned Kind quota-resync configuration was not applied; refusing setup'}
    Mutate @('create','-f','examples/kubernetes/workload.yaml')
    $owner.namespaceUID=Kube @('get','namespace','themis-test','-o','jsonpath={.metadata.uid}');SaveOwner $owner
    Mutate @('apply','-f','config/crd/verificationruns.yaml')
    Kube @('wait','--for=condition=Established','crd/verificationruns.verification.themis.dev','--timeout=60s')
    Mutate @('apply','-f','config/kubernetes/admission.yaml')
    Mutate @('apply','-f','config/kubernetes/quota.yaml')
    Kube @('wait','--for=jsonpath={.status.hard.pods}=8','resourcequota/themis-test-budget','-n','themis-test','--timeout=60s')
    # CRD discovery/quota initialization is asynchronous and independent of the
    # built-in Pod quota. Wait for the custom-resource counter explicitly.
    $quotaReady=$false
    for($quotaStart=[DateTime]::UtcNow;([DateTime]::UtcNow-$quotaStart).TotalSeconds -lt 90;){
        $quota=(Kube @('get','resourcequota','themis-test-budget','-n','themis-test','-o','json'))-join "`n"|ConvertFrom-Json
        if($quota.status.hard.'count/verificationruns.verification.themis.dev' -eq '32' -and $null -ne $quota.status.used.'count/verificationruns.verification.themis.dev'){$quotaReady=$true;break}
        Start-Sleep -Milliseconds 300
    }
    if(-not $quotaReady){throw 'VerificationRun quota initialization timed out; no experiment permitted'}
    Mutate @('apply','-f','config/kubernetes/rbac.yaml')
    $serviceAccount=PrivateFile 'runner-service-account.yaml' "apiVersion: v1`nkind: ServiceAccount`nmetadata: {name: themis-runner, namespace: themis-test}`nautomountServiceAccountToken: false`n"
    Mutate @('create','-f',$serviceAccount)
    $operatorUID=Kube @('get','serviceaccount','themis-runner','-n','themis-test','-o','jsonpath={.metadata.uid}')
    $operator=[ordered]@{name='system:serviceaccount:themis-test:themis-runner';uid=$operatorUID}
    $fixtureConfig=[ordered]@{clusterUID=$owner.clusterUID;namespaceUID=$owner.namespaceUID;approverKey=$approval.approverKey;operator=$operator}
    $configJSON=$fixtureConfig|ConvertTo-Json -Compress -Depth 4
    $config=PrivateFile 'fixture-config.yaml' "apiVersion: v1`nkind: ConfigMap`nmetadata: {name: themis-fixture-config, namespace: themis-test}`ndata:`n  config.json: |`n    $configJSON`n"
    Mutate @('create','-f',$config)
    $pins=PrivateFile 'controller-pins.yaml' "apiVersion: v1`nkind: ConfigMap`nmetadata: {name: themis-controller-pins, namespace: themis-test}`ndata:`n  clusterUID: '$($owner.clusterUID)'`n  namespaceUID: '$($owner.namespaceUID)'`n"
    Mutate @('create','-f',$pins)
    $build=Join-Path $repository '.cache/t21-images'
    New-Item -ItemType Directory -Force -Path $build | Out-Null
    $priorOS=$env:GOOS;$priorArch=$env:GOARCH;$priorCGO=$env:CGO_ENABLED
    try {
        $env:GOOS='linux';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
        foreach($binary in @('themis-controller','themis-kube-fixture')){Tool 'go' @('build','-trimpath','-o',(Join-Path $build $binary),('./cmd/'+$binary))}
    }finally{$env:GOOS=$priorOS;$env:GOARCH=$priorArch;$env:CGO_ENABLED=$priorCGO}
    foreach($item in @(@('themis-controller','build/controller.Dockerfile'),@('themis-kube-fixture','build/kubernetes-fixture.Dockerfile'))){
        $hash=(Get-FileHash -LiteralPath (Join-Path $build $item[0]) -Algorithm SHA256).Hash.ToLowerInvariant()
        $tag=$item[0]+':t21-'+$hash
        Tool 'docker' @('build','--network','none','-f',$item[1],'-t',$tag,$build)
        $null=Owned
        Tool $kind @('load','docker-image','--name','themis-t21',$tag)
        if($item[0] -eq 'themis-controller'){$controllerImage=$tag}else{$fixtureTag='docker.io/library/'+$tag}
    }
    $null=Owned
    $listing=(Tool 'docker' @('exec','themis-t21-control-plane','ctr','-n','k8s.io','images','list',('name=='+$fixtureTag)))-join "`n"
    if($listing -notmatch '\s(sha256:[a-f0-9]{64})\s'){throw 'Imported fixture manifest digest unavailable'}
    $fixtureImage='docker.io/library/themis-kube-fixture@'+$Matches[1]
    $null=Owned
    Tool 'docker' @('exec','themis-t21-control-plane','ctr','-n','k8s.io','images','tag',$fixtureTag,$fixtureImage)
    $fixtureManifest=[IO.File]::ReadAllText((Join-Path $repository 'examples/kubernetes-experiment/fixture.yaml')).Replace('REPLACE_WITH_OWNED_FIXTURE_DIGEST',$fixtureImage)
    $fixturePath=PrivateFile 'fixture.yaml' $fixtureManifest
    Mutate @('create','-f',$fixturePath)
    $controllerManifest=[IO.File]::ReadAllText((Join-Path $repository 'config/kubernetes/controller.yaml')).Replace('themis-controller:t2.0',$controllerImage)
    $controllerPath=PrivateFile 'controller.yaml' $controllerManifest
    Mutate @('create','-f',$controllerPath)
    Kube @('rollout','status','deployment/themis-controller','-n','themis-test','--timeout=120s')
    Kube @('rollout','status','deployment/latency-fixture','-n','themis-test','--timeout=120s')
    Kube @('rollout','status','deployment/synthetic','-n','themis-test','--timeout=120s')
    $deployment=(Kube @('get','deployment','latency-fixture','-n','themis-test','-o','json'))-join "`n"|ConvertFrom-Json
    $pods=(Kube @('get','pods','-n','themis-test','-l','app=themis-latency-fixture','-o','json'))-join "`n"|ConvertFrom-Json
    if($pods.items.Count -ne 1){throw 'Exactly one synthetic fixture Pod required'}
    $pod=$pods.items[0]
    $replicaSet=@($pod.metadata.ownerReferences|Where-Object controller)[0].name
    $rbac=[IO.File]::ReadAllText((Join-Path $repository 'config/kubernetes/runner-rbac.yaml')).Replace('REPLACE_WITH_POD_NAME',$pod.metadata.name).Replace('REPLACE_WITH_REPLICA_SET_NAME',$replicaSet)
    $rolePath=PrivateFile 'runner-rbac.yaml' $rbac
    Mutate @('apply','-f',$rolePath)
    $template=[IO.File]::ReadAllText((Join-Path $repository 'examples/kubernetes-experiment/run.yaml'))
    $run=$template.Replace('REPLACE_WITH_ACTUAL_DEPLOYMENT_UID',$deployment.metadata.uid)
    $runPath=PrivateFile 'latency-run.yaml' $run
    Mutate @('create','-f',$runPath)
    Kube @('wait','--for=jsonpath={.status.phase}=PLANNED','verificationrun/latency-request','-n','themis-test','--timeout=60s')
    # Scoped token is captured directly into private config, never printed.
    $null=Owned
    $token=Kube @('create','token','themis-runner','-n','themis-test','--duration=1h')
    $admin=(Kube @('config','view','--raw','--minify','-o','json'))-join "`n"|ConvertFrom-Json
    $cluster=$admin.clusters[0].cluster
    $operatorConfig=[ordered]@{apiVersion='v1';kind='Config';clusters=@(@{name='kind-themis-t21';cluster=@{server=$cluster.server;'certificate-authority-data'=$cluster.'certificate-authority-data'}});contexts=@(@{name='kind-themis-t21';context=@{cluster='kind-themis-t21';user='themis-runner';namespace='themis-test'}});'current-context'='kind-themis-t21';users=@(@{name='themis-runner';user=@{token=$token}})}
    $null=PrivateFile 'operator-kubeconfig' ($operatorConfig|ConvertTo-Json -Depth 8)
    $executionOwner=[ordered]@{version='themis.kind-ownership/t2.1-v1';clusterName='themis-t21';context='kind-themis-t21';clusterUID=$owner.clusterUID;namespaceUID=$owner.namespaceUID;operator=$operator;approverKey=$approval.approverKey;deploymentUID=$deployment.metadata.uid;fixtureImage=$fixtureImage;fixtureImageID=$pod.status.containerStatuses[0].imageID}
    $null=PrivateFile 'execution-owner.json' ($executionOwner|ConvertTo-Json -Depth 5)
    Write-Output 'Owned themis-t21 fixture and restricted runner installed. No experiment has run.'
}finally{Pop-Location}
