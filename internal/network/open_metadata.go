package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/config"
)

// OpenMetadataBlock is coi run's open-mode metadata reject for one container
// (block_metadata_endpoint). It installs only open mode's rules
// (openModeCmds), in one table listing and one nft script; Teardown takes them
// down in one listing and one script. coi run installs no boot block and no
// input rules in open mode, so neither is touched.
type OpenMetadataBlock struct {
	ip string
}

// ApplyOpenMetadataBlock installs open mode's rules with the metadata reject
// for containerName. A stale rule or allowlist set of a container that held
// the IP before is removed in the same script. It returns nil with a warning
// when the reject cannot be installed (no usable nft, no IP, nft failed):
// open mode does not fail on that, as in SetupForContainer.
func ApplyOpenMetadataBlock(cfg *config.NetworkConfig, containerName string) (*OpenMetadataBlock, []string) {
	notEnforced := func(why string, err error) []string {
		return []string{fmt.Sprintf("Warning: block_metadata_endpoint is not enforced in open mode: %s: %v", why, err)}
	}
	if !NftUsable(cfg) {
		return nil, []string{"Warning: block_metadata_endpoint is not enforced in open mode: nft is not usable"}
	}
	ip, err := GetContainerIP(containerName)
	if err != nil {
		return nil, notEnforced("no container IP", err)
	}
	if err := applyOpenMetadataRules(ip); err != nil {
		return nil, notEnforced("nft failed", err)
	}
	return &OpenMetadataBlock{ip: ip}, nil
}

// applyOpenMetadataRules makes the coi table hold exactly open mode's rules
// with the metadata reject for ip: one listing, then one script unless they
// are in place.
func applyOpenMetadataRules(ip string) error {
	listing, err := runNFTCommand("-t", "-a", "list", "table", "ip", "coi")
	if err != nil {
		if !strings.Contains(err.Error(), "No such file or directory") {
			return err
		}
		listing = nil // no table: the output is nft's error
	}
	cmds, inPlace := openMetadataCmds(string(listing), ip)
	if inPlace {
		return nil
	}
	return runNFTScript(cmds)
}

// openMetadataCmds returns the script that makes the coi table hold exactly
// open mode's rules with the metadata reject for ip, given the table's terse
// listing ("" when there is no table); inPlace means the rules are already
// exactly those (a reused container).
func openMetadataCmds(listing, ip string) (cmds [][]string, inPlace bool) {
	chains := splitChains(listing)
	forward, hasForward := chains["forward"]
	comment := "coi-" + ip
	rules := parseChainRules(forward, comment)
	input := parseChainRules(chains["input"], comment)
	var sets []string
	for _, name := range []string{staticSetName(ip), dynamicSetName(ip), staticPortSetName(ip), dynamicPortSetName(ip)} {
		if strings.Contains(listing, "set "+name+" ") {
			sets = append(sets, name)
		}
	}
	if len(input) == 0 && len(sets) == 0 && ruleTextsEqual(rules, openModeRuleTexts(ip, true)) {
		return nil, true
	}
	if listing == "" {
		cmds = append(cmds, []string{"add", "table", "ip", "coi"})
	}
	if !hasForward {
		cmds = append(cmds, []string{
			"add", "chain", "ip", "coi", "forward",
			"{", "type", "filter", "hook", "forward", "priority", "10", ";", "policy", "accept", ";", "}",
		})
	}
	if len(parseChainRules(forward, "coi-base")) == 0 {
		cmds = append(cmds, []string{
			"add", "rule", "ip", "coi", "forward",
			"ct", "state", "established,related", "accept", "comment", `"coi-base"`,
		})
	}
	cmds = append(cmds, deleteChainRuleCmds("forward", rules)...)
	cmds = append(cmds, deleteChainRuleCmds("input", input)...)
	for _, name := range sets {
		cmds = append(cmds, []string{"delete", "set", "ip", "coi", name})
	}
	return append(cmds, openModeCmds(ip, true)...), false
}

// splitChains returns each chain's part of a table listing, by chain name.
func splitChains(listing string) map[string]string {
	chains := make(map[string]string)
	var name string
	var b strings.Builder
	flush := func() {
		if name != "" {
			chains[name] = b.String()
		}
		name = ""
		b.Reset()
	}
	for _, line := range strings.Split(listing, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "chain "):
			flush()
			name = strings.Fields(trimmed)[1]
		case trimmed == "}" && name != "":
			flush()
		case name != "":
			b.WriteString(line + "\n")
		}
	}
	flush()
	return chains
}

// Teardown deletes the container's open-mode rules.
func (b *OpenMetadataBlock) Teardown(_ context.Context, _ string) error {
	if b == nil {
		return nil
	}
	rules, err := forwardRulesWithComment("coi-" + b.ip)
	if err != nil {
		return err
	}
	return runNFTScript(deleteChainRuleCmds("forward", rules))
}
