param(
 [ValidateSet('up','refresh','down')][string]$Action='up',
 [string]$ClusterName='',
 [string]$CommandProxy=''
)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
if($Action -eq 'up' -and -not $ClusterName){$ClusterName='themis-t42-'+[guid]::NewGuid().ToString('N').Substring(0,12)}
if($ClusterName -notmatch '^themis-t42-[a-f0-9]{12}$'){throw 'Fresh exact T4.2 owned cluster name required'}
$ns='themis-dep-'+$ClusterName.Substring(11)
$state=Join-Path $repo ('.themis/'+$ClusterName)
$admin=Join-Path $state 'admin-kubeconfig'
$context='kind-'+$ClusterName
$kind=Join-Path $repo '.cache/tools/kind.exe'
if($env:OS -ne 'Windows_NT'){$kind=Join-Path $repo '.cache/tools/kind'}
$binary=Join-Path $repo '.cache/t42-work/bin/themis-dependency.exe'
if($env:OS -ne 'Windows_NT'){$binary=Join-Path $repo '.cache/t42-work/bin/themis-dependency'}
$encoding=[Text.UTF8Encoding]::new($false)
function Tool([string]$Program,[string[]]$Arguments){$preference=$ErrorActionPreference;$ErrorActionPreference='Continue';try{if($CommandProxy){$output=& $CommandProxy proxy $Program @Arguments}else{$output=& $Program @Arguments};$code=$LASTEXITCODE}finally{$ErrorActionPreference=$preference};if($code -ne 0){throw "$Program exited $code"};return $output}
function Kube([string[]]$Arguments){Tool 'kubectl' (@('--kubeconfig',$admin,'--context',$context)+$Arguments)}
function Protect([string]$Path,[bool]$Directory){
 if($env:OS -eq 'Windows_NT'){$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;if($Directory){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit='ContainerInherit,ObjectInherit'}else{$acl=[Security.AccessControl.FileSecurity]::new();$inherit='None'};$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,'None','Allow'));Set-Acl -LiteralPath $Path -AclObject $acl}else{Tool 'chmod' @($(if($Directory){'700'}else{'600'}),$Path)|Out-Null}
}
function PrivateFile([string]$Path,[string]$Content,[bool]$Update=$false){if((Test-Path -LiteralPath $Path) -and -not $Update){throw 'Private setup file already exists'};[IO.File]::WriteAllText($Path,$Content,$encoding);if(-not $Update){Protect $Path $false};return $Path}
function Owned {
 $o=Get-Content -LiteralPath (Join-Path $state 'bootstrap.json') -Raw|ConvertFrom-Json
 if($o.clusterName -ne $ClusterName -or $o.namespace -ne $ns -or -not $o.clusterUID -or -not $o.engineID -or $o.endpoint -ne $endpoint -or $o.context -ne $context -or $o.nodeID -notmatch '^[a-f0-9]{64}$' -or (Tool 'docker' @('--host',$o.endpoint,'info','--format','{{.ID}}')) -ne $o.engineID -or (Tool 'docker' @('--host',$o.endpoint,'inspect','--type','container','--format','{{.Id}}',($ClusterName+'-control-plane'))) -ne $o.nodeID){throw 'Complete original local engine/cluster ownership required'}
 if((Kube @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}')) -ne $o.clusterUID){throw 'Original cluster UID changed'}
 if($o.namespaceUID -and (Kube @('get','namespace',$ns,'-o','jsonpath={.metadata.uid}')) -ne $o.namespaceUID){throw 'Original namespace UID changed'}
 return $o
}
function SaveOwner($o){$path=Join-Path $state 'bootstrap.json';$exists=Test-Path $path;$null=PrivateFile $path ($o|ConvertTo-Json -Depth 8) $exists}
function Port { $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$listener.Start();try{return $listener.LocalEndpoint.Port}finally{$listener.Stop()} }
Push-Location $repo
$previousDockerHost=$env:DOCKER_HOST
$previousDockerContext=$env:DOCKER_CONTEXT
try{
 $endpoint=$env:DOCKER_HOST
 if($env:DOCKER_CONTEXT){throw 'DOCKER_CONTEXT must be empty; explicit local DOCKER_HOST required'}
 $allowed=if($env:OS -eq 'Windows_NT'){@('npipe:////./pipe/dockerDesktopLinuxEngine')}else{@('unix:///var/run/docker.sock','unix:///run/docker.sock',('unix://'+(Join-Path $HOME '.docker/desktop/docker.sock')))}
 if(-not $endpoint -or $endpoint -notin $allowed){throw 'Explicit admitted local Linux Docker engine endpoint required; no ambient context fallback'}
 $env:DOCKER_HOST=$endpoint;$env:DOCKER_CONTEXT=$null
 $env:GOCACHE=Join-Path $repo '.cache/go-build';$env:GOMODCACHE=Join-Path $repo '.cache/go-mod';$env:GOPATH=Join-Path $repo '.cache/go-path';$env:GOTMPDIR=Join-Path $repo '.cache/tmp'
 if($Action -eq 'down'){$null=Owned;Tool $kind @('delete','cluster','--name',$ClusterName);Write-Output 'Deleted only the original UID-verified T4.2 Kind; private records retained.';return}
 if($Action -eq 'up'){
  if((Tool $kind @('version')) -notmatch '^kind v0\.32\.0 '){throw 'Pinned Kind 0.32.0 required'}
  $existing=@(Tool $kind @('get','clusters'))
  if($existing -contains $ClusterName -or (Test-Path $state)){throw 'No adoption of existing cluster or state'}
  New-Item -ItemType Directory $state|Out-Null;Protect $state $true
  Tool 'go' @('build','-trimpath','-o',$binary,'./cmd/themis-dependency')
  $keysDir=Join-Path $state 'keys'
  $keys=(Tool $binary @('init','--state',$keysDir))-join "`n"|ConvertFrom-Json
  $ports=@{application=(Port);proxy=(Port);dependency=(Port)}
  if(@($ports.Values|Sort-Object -Unique).Count -ne 3){throw 'Unique loopback ports required'}
  $kindConfig="kind: Cluster`napiVersion: kind.x-k8s.io/v1alpha4`nnetworking: {apiServerAddress: 127.0.0.1}`nnodes:`n  - role: control-plane`n    image: kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95`n    extraPortMappings:`n"
  $i=0;foreach($role in @('application','proxy','dependency')){$kindConfig+="      - {containerPort: $((31080+$i)), hostPort: $($ports[$role]), listenAddress: '127.0.0.1', protocol: TCP}`n";$i++}
  $configPath=PrivateFile (Join-Path $state 'kind.yaml') $kindConfig
  $o=[ordered]@{version='themis.native-http-bootstrap/v1alpha1';clusterName=$ClusterName;namespace=$ns;clusterUID='';namespaceUID='';previousClusters=$existing;ports=$ports;installerKey=$keys.InstallerKey;approverKey=$keys.ApproverKey;image='';endpoint=$endpoint;context=$context;nodeID='';engineID=(Tool 'docker' @('info','--format','{{.ID}}'))};SaveOwner $o
  Tool $kind @('create','cluster','--name',$ClusterName,'--config',$configPath,'--kubeconfig',$admin,'--wait','120s');Protect $admin $false
  $o.clusterUID=Kube @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}');$o.nodeID=Tool 'docker' @('--host',$endpoint,'inspect','--type','container','--format','{{.Id}}',($ClusterName+'-control-plane'));if($o.nodeID -notmatch '^[a-f0-9]{64}$'){throw 'Original node ID required'};SaveOwner $o
  $namespacePath=PrivateFile (Join-Path $state 'namespace.yaml') "apiVersion: v1`nkind: Namespace`nmetadata:`n  name: $ns`n  labels: {themis.dev/native-dependency: owned-synthetic, pod-security.kubernetes.io/enforce: restricted}`n"
  $null=Owned;Kube @('create','-f',$namespacePath)
  $o.namespaceUID=Kube @('get','namespace',$ns,'-o','jsonpath={.metadata.uid}');SaveOwner $o
  foreach($sa in @('native-runner','native-observer','native-data')){$file=PrivateFile (Join-Path $state ($sa+'.yaml')) "apiVersion: v1`nkind: ServiceAccount`nmetadata: {name: $sa, namespace: $ns}`nautomountServiceAccountToken: false`n";$null=Owned;Kube @('create','-f',$file)}
  $runnerUID=Kube @('get','serviceaccount','native-runner','-n',$ns,'-o','jsonpath={.metadata.uid}')
  $i=0;foreach($role in @('application','proxy','dependency')){
   $service=PrivateFile (Join-Path $state ($role+'-service.yaml')) "apiVersion: v1`nkind: Service`nmetadata: {name: native-$role, namespace: $ns}`nspec:`n  type: NodePort`n  selector: {app: native-$role}`n  ports: [{port: 8080, targetPort: 8080, nodePort: $((31080+$i))}]`n"
   $null=Owned;Kube @('create','-f',$service);$i++
  }
  $proxyIP=Kube @('get','service','native-proxy','-n',$ns,'-o','jsonpath={.spec.clusterIP}')
  $configuration=[ordered]@{clusterUID=$o.clusterUID;namespaceUID=$o.namespaceUID;namespace=$ns;installerKey=$o.installerKey;approverKey=$o.approverKey;actor=('system:serviceaccount:'+$ns+':native-runner');actorUID=$runnerUID;proxyIP=$proxyIP}|ConvertTo-Json -Compress
  $config=PrivateFile (Join-Path $state 'config-map.yaml') "apiVersion: v1`nkind: ConfigMap`nmetadata: {name: native-config, namespace: $ns}`ndata:`n  config.json: |`n    $configuration`n"
  $null=Owned;Kube @('create','-f',$config)
  $build=Join-Path $repo '.cache/t42-images';New-Item -ItemType Directory -Force $build|Out-Null
  $priorOS=$env:GOOS;$priorArch=$env:GOARCH;$priorCGO=$env:CGO_ENABLED
  try{$env:GOOS='linux';$env:GOARCH='amd64';$env:CGO_ENABLED='0';Tool 'go' @('build','-trimpath','-o',(Join-Path $build 'themis-dependency-fixture'),'./cmd/themis-dependency-fixture')}finally{$env:GOOS=$priorOS;$env:GOARCH=$priorArch;$env:CGO_ENABLED=$priorCGO}
  $hash=(Get-FileHash (Join-Path $build 'themis-dependency-fixture')).Hash.ToLowerInvariant();$tag='themis-dependency-fixture:t42-'+$hash
  Tool 'docker' @('build','--network','none','-f','build/dependency-fixture.Dockerfile','-t',$tag,$build)
  $null=Owned;Tool $kind @('load','docker-image','--name',$ClusterName,$tag)
  $listing=(Tool 'docker' @('exec',($ClusterName+'-control-plane'),'ctr','-n','k8s.io','images','list',('name==docker.io/library/'+$tag)))-join "`n"
  if($listing -notmatch '\s(sha256:[a-f0-9]{64})\s'){throw 'Actual imported image digest unavailable'}
  $o.image='docker.io/library/themis-dependency-fixture@'+$Matches[1]
  $null=Owned;Tool 'docker' @('exec',($ClusterName+'-control-plane'),'ctr','-n','k8s.io','images','tag',('docker.io/library/'+$tag),$o.image);SaveOwner $o
  foreach($role in @('dependency','proxy','application')){
   $manifest=[IO.File]::ReadAllText((Join-Path $repo 'examples/native-dependency/workload.yaml')).Replace('REPLACE_ROLE',$role).Replace('REPLACE_NAMESPACE',$ns).Replace('REPLACE_IMAGE',$o.image)
   $path=PrivateFile (Join-Path $state ($role+'-workload.yaml')) $manifest
   $null=Owned;Kube @('create','-f',$path);Kube @('rollout','status',('deployment/native-'+$role),'-n',$ns,'--timeout=120s')
  }
 }
 $o=Owned
 $pods=@{};$replicaSets=@()
 foreach($role in @('application','proxy','dependency')){
  $list=(Kube @('get','pods','-n',$ns,'-l',('app=native-'+$role),'-o','json'))-join "`n"|ConvertFrom-Json
  if($list.items.Count -ne 1){throw 'Exactly one original synthetic Pod per role required'}
  $pods[$role]=$list.items[0].metadata.name;$replicaSets+=@($list.items[0].metadata.ownerReferences|Where-Object controller)[0].name
 }
 $rbac=[IO.File]::ReadAllText((Join-Path $repo 'config/kubernetes/dependency-rbac.yaml')).Replace('REPLACE_NAMESPACE',$ns).Replace('REPLACE_REPLICA_SETS',(($replicaSets|Sort-Object -Unique)-join ', ')).Replace('REPLACE_PODS',(($pods.Values|Sort-Object)-join ', '))
 $rbacFile=Join-Path $state ('rbac-'+[guid]::NewGuid().ToString('N')+'.yaml');$null=PrivateFile $rbacFile $rbac
 $null=Owned;Kube @('apply','-f',$rbacFile)
 $runnerUID=Kube @('get','serviceaccount','native-runner','-n',$ns,'-o','jsonpath={.metadata.uid}')
 $adminConfig=(Kube @('config','view','--raw','--minify','-o','json'))-join "`n"|ConvertFrom-Json;$cluster=$adminConfig.clusters[0].cluster
 foreach($role in @('installer','runner','observer')){
  $dir=Join-Path $state $role;$updating=Test-Path $dir
  if(-not $updating){New-Item -ItemType Directory $dir|Out-Null;Protect $dir $true}
  $owner=[ordered]@{version='themis.native-http-owner/v1alpha1';clusterName=$ClusterName;namespace=$ns;clusterUID=$o.clusterUID;namespaceUID=$o.namespaceUID;role=$role;actor='';actorUID='';runner=('system:serviceaccount:'+$ns+':native-runner');runnerUID=$runnerUID;installerKey=$o.installerKey;approverKey=$o.approverKey;image=$o.image;pods=$pods;endpoints=@{application=('http://127.0.0.1:'+$o.ports.application);proxy=('http://127.0.0.1:'+$o.ports.proxy);dependency=('http://127.0.0.1:'+$o.ports.dependency)}}
  if($role -eq 'installer'){if(-not $updating){Copy-Item $admin (Join-Path $dir 'kubeconfig');Protect (Join-Path $dir 'kubeconfig') $false}}else{
   $owner.actor='system:serviceaccount:'+$ns+':native-'+$role;$owner.actorUID=Kube @('get','serviceaccount',('native-'+$role),'-n',$ns,'-o','jsonpath={.metadata.uid}')
   if(-not $updating){$null=Owned;$token=Kube @('create','token',('native-'+$role),'-n',$ns,'--duration=2h');$cfg=[ordered]@{apiVersion='v1';kind='Config';clusters=@(@{name=$context;cluster=@{server=$cluster.server;'certificate-authority-data'=$cluster.'certificate-authority-data'}});contexts=@(@{name=$context;context=@{cluster=$context;user=$role;namespace=$ns}});'current-context'=$context;users=@(@{name=$role;user=@{token=$token}})};$null=PrivateFile (Join-Path $dir 'kubeconfig') ($cfg|ConvertTo-Json -Depth 8)}
  }
  $null=PrivateFile (Join-Path $dir 'owner.json') ($owner|ConvertTo-Json -Depth 8) $updating
 }
 $binding=(Tool $binary @('bind','--state',(Join-Path $state 'installer'),'--keys',(Join-Path $state 'keys')))-join "`n"
 foreach($role in @('installer','runner','observer')){$path=Join-Path $state ($role+'/binding.json');$null=PrivateFile $path $binding (Test-Path $path)}
 Write-Output "Bound the current exact native dependency identities in $ClusterName / $ns. This setup command did not execute a fault."
}finally{$env:DOCKER_HOST=$previousDockerHost;$env:DOCKER_CONTEXT=$previousDockerContext;Pop-Location}
