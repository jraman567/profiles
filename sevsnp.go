// Package "profiles" implements the CoRIM profiles for various media
// types. A profile extends the base CoRIM specification
// (https://datatracker.ietf.org/doc/draft-ietf-rats-corim/) to include
// codepoints specific to a particular scheme.
//
// This file implements AMD SEV-SNP profile extension for CoRIM as
// outlined in the spec below:
// https://datatracker.ietf.org/doc/draft-deeglaze-amd-sev-snp-corim-profile/
//
// The codepoints described in this structure are derived from AMD's
// specification for SEV-SNP below, specifically the ATTESTATION_REPORT
// structure. The comments in this file refer to data structures in
// the document below:
// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
package profiles

import (
        "github.com/veraison/corim/comid"
        "github.com/veraison/corim/corim"
        "github.com/veraison/corim/extensions"
        "github.com/veraison/eat"
)

// Represents ABI_MAJOR and ABI_MINOR in the Guest policy
type policy struct {
	AbiMajor	byte		`cbor:"-1,keyasint,omitempty" json:"sevsnpvm-policy-abi-major,omitempty"`
	AbiMinor	byte		`cbor:"-2,keyasint,omitempty" json:"sevsnpvm-policy-abi-minor,omitempty"`
}

// Represents the current and committed firmware versions: CURRENT_BUILD,
//     CURRENT_MINOR, CURRENT_MAJOR, COMMITTED_BUILD, COMMITTED_MINOR
//     and COMMITTED_MAJOR.
type fw_version struct {
	BuildNumber	uint32		`cbor:"-1,keyasint,omitempty" json:"sevsnphost-sp-fw-build-number,omitempty"`
	Major		uint32		`cbor:"-2,keyasint,omitempty" json:"sevsnphost-sp-fw-major,omitempty"`
	Minor		uint32		`cbor:"-3,keyasint,omitempty" json:"sevsnphost-sp-fw-minor,omitempty"`
}

// Represents the Reference Value extension for AMD SEV-SNP
//     Policy       - ABI_MAJOR & ABI_MINOR in Guest Policy. The
//                    remaining Guest Policy fields are represented
//                    as flags in SevSnpFlags below.
//     Vmpl         - requested VMPL for Attestation Report
//     HostData     - data provided by hypervisor
//     CurrentFw    - CurrentVersion of firmware
//     CommittedFw  - CommittedVersion of firmware
//     CurrentTcb   - Currently running TCB version (not necessarily
//                    visible/reported to guest). Can be downgraded if there's
//                    an issue with firmware using DOWNLOAD_FIRMWARE_EX command.
//     CommittedTcb - Anti rollback TCB version. Can't downgrade TCB below this.
//     LaunchTcb    - Current TCB at launch
//     ReportedTcb  - TCB viisble/reported to guest
type SevSnpRefVal struct {
	Policy		*policy		`cbor:"-1,keyasint,omitempty" json:"sevsnpvm-policy-abi,omitempty"`
	Vmpl		*uint32		`cbor:"-2,keyasint,omitempty" json:"sevsnpvm-vmpl,omitempty"`
	HostData	*string		`cbor:"-3,keyasint,omitempty" json:"sevsnpvm-host-data,omitempty"`
	CurrentFw	*fw_version	`cbor:"-4,keyasint,omitempty" json:"sevsnphost-sp-fw-current,omitempty"`
	CommittedFw	*fw_version	`cbor:"-5,keyasint,omitempty" json:"sevsnphost-sp-fw-committed,omitempty"`
	CurrentTcb	*comid.SVN	`cbor:"-6,keyasint,omitempty" json:"sevsnphost-current-tcb,omitempty"`
	CommittedTcb	*comid.SVN	`cbor:"-7,keyasint,omitempty" json:"sevsnphost-committed-tcb,omitempty"`
	LaunchTcb	*comid.SVN	`cbor:"-8,keyasint,omitempty" json:"sevsnphost-launch-tcb,omitempty"`
	ReportedTcb	*comid.SVN	`cbor:"-9,keyasint,omitempty" json:"sevsnphost-reported-tcb,omitempty"`
}

// Represents Booleans in the Reference Value extension for AMD SEV-SNP
//     Guest Policy Booleans:
//         GuestSmt              - true if SMT is allowed, false otherwise
//         GuestMigrationAgent   - true is association if Migration Agent is
//                                 allowed, false otherwise
//         GuestDebug            - true is debugging is allowed, false otherwise
//         GuestSingleSocketOnly - true is guest can be activated only on one
//                                 socket, false otherwise
//         GuestCxl              - true is CXL can be populated with devices or
//                                 memory, false otherwise
//         GuestMemAes256Xts     - true is Require AES 256 XTS for memory
//                                 encryption. false if either AES 128 XEX or
//                                 AES 256 XTS could be used for memory encryption
//         GuestRaplDisabled     - true is Running Average Power Limit (RAPL) is
//                                 disabled, false otherwise
//         GuestCiphertextHiding - true if Ciphertext hiding MUST be enabled,
//                                 false if it could be enabled/disabled
//     PLATFORM_INFO booleans
//         PlatSmtEnabled       - true is SMT is enabled in the system, false otherwise
//         PlatTsmeEnabled      - true if TSME is enabled in the system, false otherwise
//         PlatEccEnabled       - true indicates platform is using ECC, false otherwise
//         PlatRaplDisabled     - true if RAPL is disabled, false otherwise
//         PlatCiphertextHiding - true indicates platform enabled Ciplertext hiding.
type SevSnpFlags struct {
	GuestSmt		*bool	`cbor:"-1,keyasint,omitempty" json:"sevsnpvm-policy-smt-allowed,omitempty"`
	GuestMigrationAgent	*bool	`cbor:"-2,keyasint,omitempty" json:"sevsnpvm-policy-migration-agent-allowed,omitempty"`
	GuestDebug		*bool	`cbor:"-3,keyasint,omitempty" json:"sevsnpvm-policy-debug-allowed,omitempty"`
	GuestSingleSocketOnly	*bool	`cbor:"-4,keyasint,omitempty" json:"sevsnpvm-policy-single-socket-only,omitempty"`
	GuestCxl		*bool	`cbor:"-5,keyasint,omitempty" json:"sevsnpvm-policy-cxl-allowed,omitempty"`
	GuestMemAes256Xts	*bool	`cbor:"-6,keyasint,omitempty" json:"sevsnpvm-policy-mem-aes-256-xts-required,omitempty"`
	GuestRaplDisabled	*bool	`cbor:"-7,keyasint,omitempty" json:"sevsnpvm-policy-rapl-must-be-disabled,omitempty"`
	GuestCiphertextHiding	*bool	`cbor:"-8,keyasint,omitempty" json:"sevsnpvm-policy-ciphertext-hiding-must-be-enabled,omitempty"`
	PlatSmtEnabled		*bool	`cbor:"-49,keyasint,omitempty" json:"sevsnphost-smt-enabled,omitempty"`
	PlatTsmeEnabled		*bool	`cbor:"-50,keyasint,omitempty" json:"sevsnphost-tsme-enabled,omitempty"`
	PlatEccEnabled		*bool	`cbor:"-51,keyasint,omitempty" json:"sevsnphost-ecc-mem-reported-enabled,omitempty"`
	PlatRaplDisabled	*bool	`cbor:"-52,keyasint,omitempty" json:"sevsnphost-rapl-disabled,omitempty"`
	PlatCiphertextHiding	*bool	`cbor:"-52,keyasint,omitempty" json:"sevsnphost-ciphertext-hiding-enabled,omitempty"`
}

// ToDo: AMD needs to approve this
var SevSnpProfileName string = "http://amd.com/sevsnp"

func init() {
        profileID, err := eat.NewProfile(SevSnpProfileName)
        if err != nil {
                panic(err) // will not error, as the hard-coded string above is valid
        }

        extMap := extensions.NewMap().
                Add(comid.ExtReferenceValue, &SevSnpRefVal{}).
                Add(comid.ExtReferenceValueFlags, &SevSnpFlags{})

        if err := corim.RegisterProfile(profileID, extMap); err != nil {
                // will not error, assuming our profile ID is unique, and we've
                // correctly set up the extensions Map above
                panic(err)
        }
}
