package attackgraph

// Tactic represents a MITRE ATT&CK tactic (kill-chain phase).
type Tactic string

const (
	TacticReconnaissance    Tactic = "reconnaissance"
	TacticInitialAccess     Tactic = "initial_access"
	TacticExecution         Tactic = "execution"
	TacticPersistence       Tactic = "persistence"
	TacticPrivilegeEscalation Tactic = "privilege_escalation"
	TacticDefenseEvasion    Tactic = "defense_evasion"
	TacticDiscovery         Tactic = "discovery"
	TacticLateralMovement   Tactic = "lateral_movement"
	TacticCollection        Tactic = "collection"
	TacticExfiltration      Tactic = "exfiltration"
	TacticImpact            Tactic = "impact"
)

// KillChainOrder defines progression order for tactics.
var KillChainOrder = []Tactic{
	TacticReconnaissance,
	TacticInitialAccess,
	TacticExecution,
	TacticPersistence,
	TacticPrivilegeEscalation,
	TacticDefenseEvasion,
	TacticDiscovery,
	TacticLateralMovement,
	TacticCollection,
	TacticExfiltration,
	TacticImpact,
}

// Technique represents a MITRE ATT&CK technique relevant to containers.
type Technique struct {
	ID          string
	Name        string
	Tactic      Tactic
	Description string
}

// TechniqueDB is the embedded subset of MITRE ATT&CK techniques relevant to container security.
var TechniqueDB = map[string]*Technique{
	"T1059.004": {ID: "T1059.004", Name: "Unix Shell", Tactic: TacticExecution, Description: "Command execution via Unix shell"},
	"T1053.003": {ID: "T1053.003", Name: "Cron", Tactic: TacticPersistence, Description: "Scheduled task/job via cron"},
	"T1611":     {ID: "T1611", Name: "Escape to Host", Tactic: TacticPrivilegeEscalation, Description: "Container escape to host system"},
	"T1610":     {ID: "T1610", Name: "Deploy Container", Tactic: TacticExecution, Description: "Adversary deploys a new container"},
	"T1613":     {ID: "T1613", Name: "Container Discovery", Tactic: TacticDiscovery, Description: "Discover containers and orchestration"},
	"T1612":     {ID: "T1612", Name: "Build Image on Host", Tactic: TacticDefenseEvasion, Description: "Build a malicious container image on host"},
	"T1552.001": {ID: "T1552.001", Name: "Credentials in Files", Tactic: TacticCollection, Description: "Search filesystem for credentials"},
	"T1046":     {ID: "T1046", Name: "Network Service Scan", Tactic: TacticDiscovery, Description: "Scan for network services"},
	"T1190":     {ID: "T1190", Name: "Exploit Public App", Tactic: TacticInitialAccess, Description: "Exploit public-facing application"},
	"T1021.004": {ID: "T1021.004", Name: "SSH", Tactic: TacticLateralMovement, Description: "Remote services via SSH"},
	"T1048":     {ID: "T1048", Name: "Exfiltration Over Alternative Protocol", Tactic: TacticExfiltration, Description: "Data exfiltration via non-C2 channel"},
	"T1070.004": {ID: "T1070.004", Name: "File Deletion", Tactic: TacticDefenseEvasion, Description: "Delete files to remove indicators"},
	"T1105":     {ID: "T1105", Name: "Ingress Tool Transfer", Tactic: TacticExecution, Description: "Download tools into environment"},
	"T1014":     {ID: "T1014", Name: "Rootkit", Tactic: TacticDefenseEvasion, Description: "Hide system artifacts via rootkit"},
	"T1082":     {ID: "T1082", Name: "System Information Discovery", Tactic: TacticDiscovery, Description: "Discover system information"},
	"T1083":     {ID: "T1083", Name: "File and Directory Discovery", Tactic: TacticDiscovery, Description: "Enumerate files and directories"},
	"T1057":     {ID: "T1057", Name: "Process Discovery", Tactic: TacticDiscovery, Description: "List running processes"},
	"T1049":     {ID: "T1049", Name: "System Network Connections", Tactic: TacticDiscovery, Description: "Enumerate network connections"},
	"T1543.002": {ID: "T1543.002", Name: "Systemd Service", Tactic: TacticPersistence, Description: "Create systemd service for persistence"},
	"T1098":     {ID: "T1098", Name: "Account Manipulation", Tactic: TacticPersistence, Description: "Manipulate accounts for persistence"},
	"T1078":     {ID: "T1078", Name: "Valid Accounts", Tactic: TacticInitialAccess, Description: "Use valid credentials"},
	"T1071.001": {ID: "T1071.001", Name: "Web Protocols", Tactic: TacticExfiltration, Description: "C2 or exfil over HTTP/S"},
	"T1569.002": {ID: "T1569.002", Name: "Service Execution", Tactic: TacticExecution, Description: "Execute via system service"},
	"T1068":     {ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactic: TacticPrivilegeEscalation, Description: "Exploit vulnerability for elevated privileges"},
	"T1548.001": {ID: "T1548.001", Name: "Setuid/Setgid", Tactic: TacticPrivilegeEscalation, Description: "Abuse setuid/setgid binaries"},
	"T1055":     {ID: "T1055", Name: "Process Injection", Tactic: TacticPrivilegeEscalation, Description: "Inject code into processes"},
	"T1095":     {ID: "T1095", Name: "Non-Application Layer Protocol", Tactic: TacticExfiltration, Description: "C2 via raw network protocols"},
	"T1027":     {ID: "T1027", Name: "Obfuscated Files", Tactic: TacticDefenseEvasion, Description: "Obfuscate payloads"},
	"T1074":     {ID: "T1074", Name: "Data Staged", Tactic: TacticCollection, Description: "Stage collected data before exfiltration"},
	"T1485":     {ID: "T1485", Name: "Data Destruction", Tactic: TacticImpact, Description: "Destroy data for impact"},
	"T1489":     {ID: "T1489", Name: "Service Stop", Tactic: TacticImpact, Description: "Stop services for impact"},
	"T1496":     {ID: "T1496", Name: "Resource Hijacking", Tactic: TacticImpact, Description: "Cryptomining or other resource abuse"},
}

// TacticIndex returns the kill-chain order index for a tactic (0 = earliest).
func TacticIndex(t Tactic) int {
	for i, kt := range KillChainOrder {
		if kt == t {
			return i
		}
	}
	return -1
}
