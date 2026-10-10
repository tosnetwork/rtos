import { AppGlobals } from "./globals";
import { SingleNominator } from "../wrappers/SingleNominator";
import { Address, fromNano, toNano } from "@ton/core";
import { checkEnvs, input } from "./utils";
import * as fs from "fs";
import { collectPoolTargets, NodectlConfig } from "./rtosctlConfig";

function parseAddress(input: string): Address {
  try {
    return Address.parseRaw(input);
  } catch {
    return Address.parse(input);
  }
}

export async function run() {
  const master = (await AppGlobals.S()).getMasterWallet();
  await master.updateSeqno();
  console.log(`Master wallet address: ${master.getAddress()}`);

  const envPath = process.env.RTOSCTL_CONFIG_PATH;
  const configPath = envPath ?? await input("Enter rtosctl config file path: ");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8")) as NodectlConfig;
  const pools = collectPoolTargets(config);
  if (pools.length === 0) {
    throw new Error("No pool addresses found in config (checked pools/bindings and elections.pools)");
  }
  console.log(`Total pools: ${pools.length}`);
  const envAmount = process.env.RTOSCTL_INITIAL_BALANCE;
  const amount = envAmount ? toNano(envAmount) : toNano(await input("Enter amount (TOS): "));
  console.log(`topup amount: ${fromNano(amount)} TOS`);

  for (const pool of pools) {
    const nominator = SingleNominator.createFromAddress(parseAddress(pool.address));
    console.log(`Topping up pool ${pool.name} ${nominator.address.toRawString()} with ${fromNano(amount)} TOS`);
    let seqno = master.getSeqno();
    await master.sendTon(nominator.address, amount, undefined);
    console.log(`Wait for transfer...`);
    await master.waitForSeqNoChange(seqno, 100);
  }

  console.log(`Done`);
}

(async () => {
  checkEnvs();
  await run();
})();
