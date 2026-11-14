#!/bin/bash
set -e

# This test uses Plain (inline) keys in config.json. An external vault would
# accumulate validator keys across runs; ensure each run starts clean.
unset VAULT_URL

NODES=6
WORKCHAINS=false
CURRENT_BRANCH="$(git branch --show-current)"
TEST_ROOT=$(pwd);
NODE_TARGET=$TEST_ROOT/../../../target/release/

echo "Current branch: $CURRENT_BRANCH"
echo "Current root: $TEST_ROOT"

# apt update
# apt install jq

if [ "$WORKCHAINS" == "true" ]
then
    echo "Workchains are enabled!"
else
    echo "Workchains are NOT enabled!"
fi

echo "Preparations..."

pkill -9 node_singlehost > /dev/null 2>&1 || echo "No node processes"

bash ./remove_junk.sh "$NODES" > /dev/null 2>&1
echo "Building $(pwd) (build flags: \"$NODE_BUILD_FLAGS\")"

if ! cargo build --release $NODE_BUILD_FLAGS
then
    exit 1
fi
if ! cargo build --release $NODE_BUILD_FLAGS -p rtos --example test_net_prepare
then
    exit 1
fi
cp $NODE_TARGET/rtos $NODE_TARGET/node_singlehost

cd $TEST_ROOT
NOWDATE=$(date +"%s")
# NOWIP=$(curl ifconfig.me)
NOWIP="127.0.0.1"
echo "  IP = $NOWIP"

# Placeholder config for offline config generation; no node starts against it.
cat $TEST_ROOT/ton-global.config_1.json > $NODE_TARGET/ton-global.config.json
cat $TEST_ROOT/ton-global.config_2.json >> $NODE_TARGET/ton-global.config.json

mkdir -p tmp > /dev/null 2>&1
rm -frd tmp/* > /dev/null 2>&1
mkdir -p tmp/blocks > /dev/null 2>&1

# 0 is full node
for (( N=0; N <= $NODES; N++ ))
do
    cd $NODE_TARGET

    echo "Cleaning up #$N..."
    rm -frd node_db_$N > /dev/null 2>&1
    rm -frd configs_$N > /dev/null 2>&1
    rm -f $TEST_ROOT/tmp/output_$N.log > /dev/null 2>&1

    echo "Validator's #$N config generating..."

    ./crypto gen key > $TEST_ROOT/tmp/genkey$N
    jq -c '{type_id: 1209251014, pub_key: .pubkey}' $TEST_ROOT/tmp/genkey$N > console_public_json
    rm -f config.json > /dev/null 2>&1
    rm -f default_config.json > /dev/null 2>&1
    rm -f console_config.json > /dev/null 2>&1
    sed "s/NODE_NUM/$N/g" $TEST_ROOT/log_cfg.yml > $NODE_TARGET/log_cfg_$N.yml

    if [ $N -ne 0 ]; then
        cp $TEST_ROOT/default_config.json default_config.json
    else 
        cp $TEST_ROOT/default_config_fullnode.json default_config.json
    fi

    sed "s/nodenumber/$N/g" default_config.json > default_config$N.json
    sed "s/0.0.0.0/$NOWIP/g" default_config$N.json > default_config.json
    PORT=$(( 3000 + $N ))
    sed "s/main_port/$PORT/g" default_config.json > default_config$N.json
    QUIC_PORT=$(( 5000 + $N ))
    sed -i "s/quic_port/$QUIC_PORT/g" default_config$N.json
    PORT=$(( 4920 + $N ))
    sed "s/control_port/$PORT/g" default_config$N.json > default_config.json
    PORT=$(( 4000 + $N ))
    sed "s/lite_port/$PORT/g" default_config.json > default_config$N.json
    mv default_config$N.json default_config.json

    if [ "$WORKCHAINS" == "true" ]
    then
        if [ $N -gt 10 ]
        then
            sed "s/workchain_id/\"workchain\": 1,/g" default_config.json > default_config$N.json
        elif [ $N -gt 5 ] || [ $N -eq 0 ]
        then
            sed "s/workchain_id/\"workchain\": 0,/g" default_config.json > default_config$N.json
        else
            sed "s/workchain_id/\"workchain\": -1,/g" default_config.json > default_config$N.json
        fi
    else
        sed "s/workchain_id//g" default_config.json > default_config$N.json
    fi

    cp default_config$N.json default_config.json
    cp $NODE_TARGET/default_config$N.json $TEST_ROOT/tmp/default_config$N.json

    rm -f tmp_output > /dev/null 2>&1
    # The node creates config.json and console_config.json, then exits.
    if ! ./node_singlehost --configs . --ckey "$(cat console_public_json)" > tmp_output_generate 2>&1; then
        echo "ERROR: node config generation failed"
        exit 1
    fi
    if [ ! -f "console_config.json" ]; then
        echo "ERROR: console_config.json does not exist"
        exit 1
    fi

    cp console_config.json $TEST_ROOT/tmp/console$N.json
    cd $NODE_TARGET
    jq ".client_key = $(jq '{type_id: 1209251014, pvt_key: .secret}' $TEST_ROOT/tmp/genkey$N)" "$TEST_ROOT/tmp/console$N.json" > "$TEST_ROOT/tmp/console$N.tmp.json"
    jq ".config = $(cat $TEST_ROOT/tmp/console$N.tmp.json)" "$TEST_ROOT/console-template.json" > "$TEST_ROOT/tmp/console$N.json"
    rm -f $TEST_ROOT/tmp/console$N.tmp.json

    rm -f tmp_output_console > /dev/null 2>&1
    
    # 0 is full node
    cp $NODE_TARGET/config.json $TEST_ROOT/tmp/config$N.json
    if [ $N -ne 0 ]; then
        # Prepare public test consensus keys offline; never open a database
        # against the placeholder genesis used only for config generation.
        ./examples/test_net_prepare --config "$TEST_ROOT/tmp/config$N.json" \
            --member "$N" --custody "$TEST_ROOT/tmp/custody$N" \
            --descriptor "$TEST_ROOT/tmp/validator$N.json"
    fi

done

echo "Zerostate generating..."

if [ "$WORKCHAINS" == "true" ]
then
    sed "s/nowdate/$NOWDATE/g" $TEST_ROOT/zero_state_blanc_1_2wcs.json > $TEST_ROOT/tmp/zero_state_tmp.json
else
    sed "s/nowdate/$NOWDATE/g" $TEST_ROOT/zero_state_blanc_1.json > $TEST_ROOT/tmp/zero_state_tmp.json
fi

TOTAL_WEIGHT=$(( NODES * 10 ))
sed "s/p34_total_weight/$TOTAL_WEIGHT/g" $TEST_ROOT/tmp/zero_state_tmp.json > $TEST_ROOT/tmp/zero_state_tmp_2.json
sed "s/p34_total/$NODES/g" $TEST_ROOT/tmp/zero_state_tmp_2.json > $TEST_ROOT/tmp/zero_state.json

for (( N=1; N <= $NODES; N++ ))
do
    echo "  Validator #$N contract processing..."

    cat "$TEST_ROOT/tmp/validator$N.json" >> "$TEST_ROOT/tmp/zero_state.json"
    if [ ! $N -eq $NODES ]
    then
        printf ",\n" >> $TEST_ROOT/tmp/zero_state.json
    fi

done

cat $TEST_ROOT/zero_state_blanc_2.json >> $TEST_ROOT/tmp/zero_state.json

echo "  finish zerostate generating..."
rm -f *.boc > /dev/null 2>&1
./zerostate $TEST_ROOT/tmp/zero_state.json
# Rename output BOC files to {hex_file_hash}.boc as expected by the node (-z flag)
ZS_HASH=$(jq -r '.zero_state.file_hash' config.json | base64 -d | xxd -p -c 32)
mv zerostate.boc "${ZS_HASH}.boc"
BS_HASH=$(jq -r '.base_state.file_hash' config.json | base64 -d | xxd -p -c 32)
mv basestate0.boc "${BS_HASH}.boc"

echo "Global config generating..."

cd $TEST_ROOT
cat ton-global.config_1.json >> tmp/ton-global.config.json
cd $NODE_TARGET

for (( N=1; N <= $NODES; N++ ))
do
    echo "  Validator #$N DHT key processing..."

    # DHT key is the first one in config (tag 1)
    KEYTAG=$(grep "pvt_key" $TEST_ROOT/tmp/config$N.json | head -n1 | cut -c 23-66)

    PORT=$(( 3000 + $N ))
    ./crypto gen dht --addr $NOWIP:$PORT --key $KEYTAG >> $TEST_ROOT/tmp/ton-global.config.json
    
    if [ ! $N -eq $NODES ]
    then
        echo "," >> $TEST_ROOT/tmp/ton-global.config.json
    fi

done

cat $TEST_ROOT/ton-global.config_2.json >> $TEST_ROOT/tmp/ton-global.config.json
jq ".validator.zero_state = $(jq .zero_state $NODE_TARGET/config.json)" "$TEST_ROOT/tmp/ton-global.config.json" > "$TEST_ROOT/tmp/ton-global.config.json.tmp"
# Looks like jq contains bug which converts big number wrong way, rolling back:
sed "s/-9223372036854776000/-9223372036854775808/g" $TEST_ROOT/tmp/ton-global.config.json.tmp > $TEST_ROOT/tmp/ton-global.config.json
cp $TEST_ROOT/tmp/ton-global.config.json $NODE_TARGET/ton-global.config.json

echo "Starting nodes..."

cd $NODE_TARGET

for (( N=0; N <= $NODES; N++ ))
do
    echo "  Starting node #$N..."

    rm -frd $NODE_TARGET/configs_$N > /dev/null 2>&1
    mkdir -p $NODE_TARGET/configs_$N
    cp $TEST_ROOT/tmp/config$N.json $NODE_TARGET/configs_$N/config.json
    cp $TEST_ROOT/tmp/default_config$N.json $NODE_TARGET/configs_$N/default_config.json
    cp $TEST_ROOT/tmp/console$N.json $NODE_TARGET/configs_$N/console.json
    sed "s/NODE_NUM/$N/g ; s#/shared/#$TEST_ROOT/tmp/#" "$TEST_ROOT/log_cfg.yml" > "$NODE_TARGET/configs_$N/log_cfg_$N.yml"
    cp $TEST_ROOT/tmp/ton-global.config.json $NODE_TARGET/configs_$N/ton-global.config.json

    # rm $TEST_ROOT/tmp/output_$N.log
    ./node_singlehost --configs configs_$N -z . > "$TEST_ROOT/tmp/output_$N.log" 2>&1 &

done

date
echo "Started"
