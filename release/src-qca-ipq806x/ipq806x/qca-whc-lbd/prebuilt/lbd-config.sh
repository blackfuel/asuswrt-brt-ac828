#
# @@-COPYRIGHT-START-@@
#
# Copyright (c) 2015 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
# @@-COPYRIGHT-END-@@
#

. /lib/functions/whc-debug.sh
. /lib/functions/whc-iface.sh

# Append a config parameter to the file
# input: $1 - parameter string to append (key and value)
# input: $2 - filename to append to
__lbd_cfg_append() {
	echo "$1" >> "$2"
}

# Append a config parameter to the file preceded by a newline
# input: $1 - parameter string to append (key and value)
# input: $2 - filename to append to
__lbd_cfg_nl_append() {
	echo "" >> "$2"
	echo "$1" >> "$2"
}

# __lbd_cfg_add_str <section> <option> <filename>
__lbd_cfg_add_str() {
	local key="$2"
	local section="$1"
	local option="$2"
	local filename="$3"

	config_get val "${section}" "${option}"
	[ -n "${val}" ] && __lbd_cfg_append "${key}=${val}" $filename
}

# Add a string to the config file where the key in the UCI config is
# different from the config in the generated config.
# input: $1 - section name in UCI
# input: $2 - parameter name in UCI
# input: $3 - parameter name in the generated configuration
# input: $4 - output filename
__lbd_cfg_add_str_new_key() {
	local section="$1"
	local option="$2"
	local newkey="$3"
	local filename="$4"

	config_get val "${section}" "${option}"
	[ -n "${val}" ] && __lbd_cfg_append "${newkey}=${val}" $filename
}

# Given two (section, key) pairs, subtract the second value from the first
# to arrive at an RSSI value and use that for the key being generated.
# This is meant to convert an RSSI on one band to an RSSI on the
# other band, albeit in such a way that is the mirror image of the estimates
# performed by lbd.
# To prevent value underflow/overflow, use 0 for the key if the base value
# is smaller than the adjust value; use 255 if the base value subtracts the
# adjust value is greater than 255
#
# The last parameter is the file to output.
__lbd_cfg_add_rssi_est_str() {
	local basevalsection="$1"
	local basevalkey="$2"
	local adjvalsection="$3"
	local adjvalkey="$4"
	local newkey="$5"
	local filename="$6"

	config_get baseval "${basevalsection}" "${basevalkey}"
	config_get adjval  "${adjvalsection}" "${adjvalkey}"
	if [ -n "${baseval}" ] && [ -n "${adjval}" ]; then
		if [ "${baseval}" -gt "${adjval}" ] && \
		   [ "${baseval}" -lt "$((255 + $adjval))" ]; then
			val="$(($baseval - $adjval))"
		elif [ "${baseval}" -le "${adjval}" ]; then
			val="0"
		elif [ "${baseval}" -ge "$((255 + $adjval))" ]; then
			val="255"
		fi
	fi

	[ -n "${val}" ] && __lbd_cfg_append "${newkey}=${val}" $filename
}

__lbd_cfg_add_head() {
	local filename=$1
	local append_only=$2

	if [ "$append_only" -gt 0 ]; then
		echo ";"	>> "$filename"
		__lbd_cfg_append '' $filename  # extra blank lines to demark the WLB params
		__lbd_cfg_append ';  ' $filename
		__lbd_cfg_append ';  Automatically generated Wi-Fi load balancing configuration' $filename
	else
		echo ";"	> "$filename"
		__lbd_cfg_append ';  Automatically generated lbd config file,do not change it.' $filename
		fi

	__lbd_cfg_append ';' $filename
	__lbd_cfg_append ';WLANIF		list of wlan interfaces' $filename
	__lbd_cfg_append ';WLANIF2G		wlan driver interface for 2.4 GHz band' $filename
	__lbd_cfg_append ';WLANIF5G		wlan driver interface for 5 GHz band' $filename
	__lbd_cfg_append ';STADB:		station database' $filename
	__lbd_cfg_append ';STAMON:		station monitor' $filename
	__lbd_cfg_append ';BANDMON:		band monitor' $filename
	__lbd_cfg_append ';ESTIMATOR:		rate estimator' $filename
	__lbd_cfg_append ';STEEREXEC:		steering executor' $filename
	__lbd_cfg_append ';STEERALG:		steering algorithm' $filename
	__lbd_cfg_append ';DIAGLOG:		diagnostic logging' $filename
}

# Add the list of managed interfaces to the configuration file.
# input: $1 - the name of the config file to write to
__lbd_cfg_add_interface() {
	local filename="$1"
	local section="config"
	local option="MatchingSSID"

	config_get ssid "${section}" "${option}"

	local all_wlan_ifaces

	# Get a list of wlan interfaces, seperated by comma
	whc_get_wlan_ifaces all_wlan_ifaces $ssid
	__lbd_cfg_append 'WlanInterfaces='$all_wlan_ifaces $filename
}

lbd_create_config() {
	local filename=$1
	local multi_ap_mode=$2
	local multi_ap_cap=0
	if [ "$multi_ap_mode" -gt 0 ]; then
		let multi_ap_cap=$3
	fi

	config_load 'lbd'
	__lbd_cfg_add_head $filename $multi_ap_mode # append config instead of truncating in multi AP mode

	__lbd_cfg_nl_append '[WLANIF]' $filename
	__lbd_cfg_add_interface $filename

	__lbd_cfg_nl_append '[WLANIF2G]' $filename
	__lbd_cfg_add_str_new_key	IdleSteer	NormalInactTimeout	InactIdleThreshold $filename
	__lbd_cfg_add_str_new_key	IdleSteer	OverloadInactTimeout	InactOverloadThreshold $filename
	__lbd_cfg_add_str	IdleSteer	InactCheckInterval $filename
	__lbd_cfg_add_rssi_est_str	IdleSteer	RSSISteeringPoint_UG	Estimator_Adv	RSSIDiff_EstW5FromW2	InactRSSIXingHighThreshold $filename
	__lbd_cfg_add_str	SteerExec_Adv	LowRSSIXingThreshold $filename
	__lbd_cfg_add_str	Estimator_Adv	BcnrptActiveDuration $filename
	__lbd_cfg_add_str	Estimator_Adv	BcnrptPassiveDuration $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	TxRateXingThreshold_UG	HighTxRateXingThreshold $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	RateRSSIXingThreshold_UG	HighRateRSSIXingThreshold $filename
	if [ "$multi_ap_mode" -gt 0 ]; then
		# Only include AP steering parameters for multi-AP setup
		if [ "$multi_ap_cap" -gt 0 ]; then
			__lbd_cfg_add_str_new_key	APSteer	LowRSSIAPSteerThreshold_CAP	LowRSSIAPSteeringThreshold	$filename
		else
			__lbd_cfg_add_str_new_key	APSteer	LowRSSIAPSteerThreshold_RE	LowRSSIAPSteeringThreshold	$filename
		fi
	else
		# Only include MU check interval to enable ACS report in single-AP setup
		__lbd_cfg_add_str_new_key	BandMonitor_Adv	MUCheckInterval_W2	MUCheckInterval $filename
		__lbd_cfg_add_str	Offload		MUAvgPeriod $filename
	fi

	 __lbd_cfg_nl_append '[WLANIF5G]' $filename
	__lbd_cfg_add_str_new_key	IdleSteer	NormalInactTimeout	InactIdleThreshold $filename
	__lbd_cfg_add_str_new_key	IdleSteer	OverloadInactTimeout	InactOverloadThreshold $filename
	__lbd_cfg_add_str	IdleSteer	InactCheckInterval $filename
	__lbd_cfg_add_str_new_key	IdleSteer	RSSISteeringPoint_UG	InactRSSIXingHighThreshold $filename
	__lbd_cfg_add_rssi_est_str	IdleSteer	RSSISteeringPoint_DG	Estimator_Adv	RSSIDiff_EstW2FromW5	InactRSSIXingLowThreshold $filename
	__lbd_cfg_add_str	SteerExec_Adv	LowRSSIXingThreshold $filename
	__lbd_cfg_add_str	Estimator_Adv	BcnrptActiveDuration $filename
	__lbd_cfg_add_str	Estimator_Adv	BcnrptPassiveDuration $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	TxRateXingThreshold_DG	LowTxRateXingThreshold $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	RateRSSIXingThreshold_DG	LowRateRSSIXingThreshold $filename
	if [ "$multi_ap_mode" -gt 0 ]; then
		# Only include AP steering parameters for multi-AP setup
		if [ "$multi_ap_cap" -gt 0 ]; then
			__lbd_cfg_add_str_new_key	APSteer	LowRSSIAPSteerThreshold_CAP	LowRSSIAPSteeringThreshold	$filename
		else
			__lbd_cfg_add_str_new_key	APSteer	LowRSSIAPSteerThreshold_RE	LowRSSIAPSteeringThreshold	$filename
		fi
	else
		# Only include MU check interval to enable ACS report in single-AP setup
		__lbd_cfg_add_str_new_key	BandMonitor_Adv	MUCheckInterval_W5	MUCheckInterval $filename
		__lbd_cfg_add_str	Offload		MUAvgPeriod $filename
	fi

	__lbd_cfg_nl_append '[STADB]' $filename
	__lbd_cfg_add_str	StaDB		IncludeOutOfNetwork $filename
	__lbd_cfg_add_str	StaDB_Adv	AgingSizeThreshold $filename
	__lbd_cfg_add_str	StaDB_Adv	AgingFrequency $filename
	__lbd_cfg_add_str	StaDB_Adv	OutOfNetworkMaxAge $filename
	__lbd_cfg_add_str	StaDB_Adv	InNetworkMaxAge $filename
	__lbd_cfg_add_str_new_key	config_Adv	AgeLimit	ProbeMaxInterval $filename
	if [ "$multi_ap_mode" -gt 0 ]; then
		# Only set number of supported remote radios for multi-AP setup
		__lbd_cfg_add_str	StaDB_Adv	NumRemoteBSSes		$filename
	fi

	__lbd_cfg_nl_append '[STAMON]' $filename
	__lbd_cfg_add_str	StaMonitor_Adv	RSSIMeasureSamples_W2 $filename
	__lbd_cfg_add_str	StaMonitor_Adv	RSSIMeasureSamples_W5 $filename
	__lbd_cfg_add_str	config_Adv	AgeLimit $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	TxRateXingThreshold_UG	HighTxRateXingThreshold $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	RateRSSIXingThreshold_UG	HighRateRSSIXingThreshold $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	TxRateXingThreshold_DG	LowTxRateXingThreshold $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	RateRSSIXingThreshold_DG	LowRateRSSIXingThreshold $filename
	if [ "$multi_ap_mode" -gt 0 ]; then
		# Parameters only relevant for multi-AP setup
		__lbd_cfg_add_str	IdleSteer	RSSISteeringPoint_DG	$filename
		if [ "$multi_ap_cap" -gt 0 ]; then
			__lbd_cfg_add_str_new_key	APSteer	LowRSSIAPSteerThreshold_CAP	LowRSSIAPSteeringThreshold	$filename
		else
			__lbd_cfg_add_str_new_key	APSteer	LowRSSIAPSteerThreshold_RE	LowRSSIAPSteeringThreshold	$filename
		fi
	fi

	__lbd_cfg_nl_append '[BANDMON]' $filename
	__lbd_cfg_add_str	Offload		MUOverloadThreshold_W2 $filename
	__lbd_cfg_add_str	Offload		MUOverloadThreshold_W5 $filename
	__lbd_cfg_add_str	Offload		MUSafetyThreshold_W2 $filename
	__lbd_cfg_add_str	Offload		MUSafetyThreshold_W5 $filename
	__lbd_cfg_add_str_new_key	Offload	OffloadingMinRSSI	RSSISafetyThreshold $filename
	__lbd_cfg_add_str_new_key	config_Adv	AgeLimit	RSSIMaxAge $filename
	__lbd_cfg_add_str	BandMonitor_Adv	ProbeCountThreshold $filename
	if [ "$multi_ap_mode" -gt 0 ]; then
		# Parameters only relevant for multi-AP setup
		if [ "$multi_ap_cap" -gt 0 ]; then
			# Parameters only relevant for CAP
			__lbd_cfg_add_str	BandMonitor_Adv	MUReportPeriod	$filename
		fi
		__lbd_cfg_add_str	BandMonitor_Adv	LoadBalancingAllowedMaxPeriod	$filename
		__lbd_cfg_add_str	BandMonitor_Adv	NumRemoteChannels	$filename
	fi

	__lbd_cfg_nl_append '[ESTIMATOR]' $filename
	__lbd_cfg_add_str	config_Adv	AgeLimit $filename
	__lbd_cfg_add_str	Estimator_Adv	RSSIDiff_EstW5FromW2 $filename
	__lbd_cfg_add_str	Estimator_Adv	RSSIDiff_EstW2FromW5 $filename
	__lbd_cfg_add_str	Estimator_Adv	ProbeCountThreshold $filename
	__lbd_cfg_add_str	Estimator_Adv	StatsSampleInterval $filename
	__lbd_cfg_add_str	Estimator_Adv	11kProhibitTimeShort $filename
	__lbd_cfg_add_str	Estimator_Adv	11kProhibitTimeLong $filename
	__lbd_cfg_add_str	Estimator_Adv	PhyRateScalingForAirtime $filename
	__lbd_cfg_add_str	Estimator_Adv	EnableContinuousThroughput $filename

	__lbd_cfg_nl_append '[STEEREXEC]' $filename
	__lbd_cfg_add_str	SteerExec	SteeringProhibitTime $filename
	__lbd_cfg_add_str	SteerExec_Adv	TSteering $filename
	__lbd_cfg_add_str	SteerExec_Adv	InitialAuthRejCoalesceTime $filename
	__lbd_cfg_add_str	SteerExec_Adv	AuthRejMax $filename
	__lbd_cfg_add_str	SteerExec_Adv	SteeringUnfriendlyTime $filename
	__lbd_cfg_add_str	SteerExec_Adv	MaxSteeringUnfriendly $filename
	__lbd_cfg_add_str_new_key	SteerExec_Adv	LowRSSIXingThreshold	LowRSSIXingThreshold_W2 $filename
	__lbd_cfg_add_str_new_key	SteerExec_Adv	LowRSSIXingThreshold	LowRSSIXingThreshold_W5 $filename
	__lbd_cfg_add_str	SteerExec_Adv	TargetLowRSSIThreshold_W2 $filename
	__lbd_cfg_add_str	SteerExec_Adv	TargetLowRSSIThreshold_W5 $filename
	__lbd_cfg_add_str	SteerExec_Adv	BlacklistTime $filename
	__lbd_cfg_add_str	SteerExec_Adv	BTMResponseTime $filename
	__lbd_cfg_add_str	SteerExec_Adv	BTMAssociationTime $filename
	__lbd_cfg_add_str	SteerExec_Adv	BTMAlsoBlacklist $filename
	__lbd_cfg_add_str	SteerExec_Adv	BTMUnfriendlyTime $filename
	__lbd_cfg_add_str	SteerExec	BTMSteeringProhibitShortTime $filename
	__lbd_cfg_add_str	SteerExec_Adv	MaxBTMUnfriendly $filename
	__lbd_cfg_add_str	SteerExec_Adv	MaxBTMActiveUnfriendly $filename
	__lbd_cfg_add_str	config_Adv	AgeLimit $filename
	__lbd_cfg_add_str	SteerExec_Adv	MinRSSIBestEffort $filename

	__lbd_cfg_nl_append '[STEERALG]' $filename
	__lbd_cfg_add_str_new_key	IdleSteer	RSSISteeringPoint_DG	InactRSSIXingThreshold_W2 $filename
	__lbd_cfg_add_str_new_key	IdleSteer	RSSISteeringPoint_UG	InactRSSIXingThreshold_W5 $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	TxRateXingThreshold_UG	HighTxRateXingThreshold $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	RateRSSIXingThreshold_UG	HighRateRSSIXingThreshold $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	TxRateXingThreshold_DG	LowTxRateXingThreshold $filename
	__lbd_cfg_add_str_new_key	ActiveSteer	RateRSSIXingThreshold_DG	LowRateRSSIXingThreshold $filename
	__lbd_cfg_add_str	SteerAlg_Adv	MinTxRateIncreaseThreshold $filename
	__lbd_cfg_add_str	config_Adv	AgeLimit $filename
	__lbd_cfg_add_str	config		PHYBasedPrioritization $filename
	__lbd_cfg_add_str_new_key	Offload	OffloadingMinRSSI	RSSISafetyThreshold $filename
	__lbd_cfg_add_str	SteerAlg_Adv	MaxSteeringTargetCount $filename
	if [ "$multi_ap_mode" -gt 0 ]; then
		# Only include AP steering parameters for multi-AP setup
		if [ "$multi_ap_cap" -gt 0 ]; then
			__lbd_cfg_add_str	APSteer	APSteerToLeafMinRSSIIncThreshold	$filename
		else
			# TODO: only consider star topology, so no more than one hop RE
			__lbd_cfg_add_str	APSteer	APSteerToRootMinRSSIIncThreshold	$filename
			__lbd_cfg_add_str	APSteer	APSteerToPeerMinRSSIIncThreshold	$filename
		fi
		__lbd_cfg_add_str	APSteer	DownlinkRSSIThreshold_W5	$filename
	fi

	__lbd_cfg_nl_append '[DIAGLOG]' $filename
	__lbd_cfg_add_str	DiagLog		EnableLog $filename
	__lbd_cfg_add_str	DiagLog		LogServerIP $filename
	__lbd_cfg_add_str	DiagLog		LogServerPort $filename
	__lbd_cfg_add_str	DiagLog		LogLevelWlanIF $filename
	__lbd_cfg_add_str	DiagLog		LogLevelBandMon $filename
	__lbd_cfg_add_str	DiagLog		LogLevelStaDB $filename
	__lbd_cfg_add_str	DiagLog		LogLevelSteerExec $filename
	__lbd_cfg_add_str	DiagLog		LogLevelStaMon $filename
	__lbd_cfg_add_str	DiagLog		LogLevelEstimator $filename
	__lbd_cfg_add_str	DiagLog		LogLevelDiagLog $filename
}
