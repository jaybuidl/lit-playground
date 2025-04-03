import { LitNodeClient } from "@lit-protocol/lit-node-client";
import { LitContracts } from "@lit-protocol/contracts-sdk";
import { LIT_ABILITY, LIT_NETWORK } from "@lit-protocol/constants";
import { Wallet } from "@ethersproject/wallet";
import { JsonRpcProvider } from "@ethersproject/providers";
import dotenv from "dotenv";
import {
  createSiweMessageWithRecaps,
  generateAuthSig,
  LitAccessControlConditionResource,
} from "@lit-protocol/auth-helpers";
import { AuthSig, AuthCallback, AuthCallbackParams, LitAbility } from "@lit-protocol/types";
import { capacityDelegationAuthSig } from "./capacityDelegationAuthSig";

dotenv.config();

const V2_EARLY_USER_NFT = "0xfE34a72c55e512601E7d491A9c5b36373cE34d63";

// Must match the identifier on https://developer.litprotocol.com/resources/supported-chains
type Chain = "arbitrum" | "arbitrumSepolia";

interface AccessControlCondition {
  contractAddress: string;
  standardContractType: string;
  chain: Chain;
  method: string;
  parameters: string[];
  returnValueTest: {
    comparator: string;
    value: string;
  };
}

class Lit {
  private litNodeClient: LitNodeClient;
  private contractClient: LitContracts;
  private chain: Chain;
  private accessControlConditions: AccessControlCondition[];
  private wallet: Wallet;

  constructor(chain: Chain) {
    this.chain = chain;
    this.accessControlConditions = [
      {
        contractAddress: V2_EARLY_USER_NFT,
        // contractAddress: "0xfE34a72c55e512601E7d491A9c5b36373cE31111",
        standardContractType: "ERC721",
        chain: this.chain,
        method: "balanceOf",
        parameters: [":userAddress"],
        returnValueTest: {
          comparator: ">",
          value: "0",
        },
      },
    ];
    const privateKey = process.env.PRIVATE_KEY;
    if (!privateKey) throw new Error("PRIVATE_KEY environment variable is required");

    // Initialize wallet client
    const provider = new JsonRpcProvider("https://yellowstone-rpc.litprotocol.com");
    this.wallet = new Wallet(privateKey, provider);

    // Initialize Lit client
    this.litNodeClient = new LitNodeClient({
      litNetwork: LIT_NETWORK.DatilDev,
      debug: false,
    });

    this.contractClient = new LitContracts({
      signer: this.wallet,
      network: LIT_NETWORK.DatilDev,
    });
  }

  async connect(): Promise<void> {
    await this.litNodeClient.connect();
    await this.contractClient.connect();
  }

  async disconnect(): Promise<void> {
    await this.litNodeClient.disconnect();
  }

  async mintCapacityCredits(): Promise<{
    capacityTokenIdStr: string;
    capacityDelegationAuthSig: AuthSig;
  }> {
    const { capacityTokenIdStr } = await this.contractClient.mintCapacityCreditsNFT({
      requestsPerKilosecond: 80,
      // requestsPerDay: 14400,
      // requestsPerSecond: 10,
      daysUntilUTCMidnightExpiration: 2,
    });
    const { capacityDelegationAuthSig } = await this.litNodeClient.createCapacityDelegationAuthSig({
      uses: "1000000000000000",
      dAppOwnerWallet: this.wallet,
      capacityTokenId: capacityTokenIdStr,
      delegateeAddresses: [this.wallet.address],
    });
    return { capacityTokenIdStr, capacityDelegationAuthSig };
  }

  async encrypt(message: string): Promise<{
    ciphertext: string;
    dataToEncryptHash: string;
  }> {
    // Convert message to Uint8Array
    const messageBytes = new TextEncoder().encode(message);

    // Encrypt the message
    const encryptedData = await this.litNodeClient.encrypt({
      dataToEncrypt: messageBytes,
      accessControlConditions: this.accessControlConditions,
    });

    return {
      ciphertext: encryptedData.ciphertext,
      dataToEncryptHash: encryptedData.dataToEncryptHash,
    };
  }

  async getSessionSignatures(capacityDelegationAuthSig: AuthSig) {
    // Get the latest blockhash
    const latestBlockhash = await this.litNodeClient.getLatestBlockhash();

    // Define the authNeededCallback function
    const authNeededCallback: AuthCallback = async (params: AuthCallbackParams) => {
      if (!params.uri) {
        throw new Error("uri is required");
      }
      if (!params.expiration) {
        throw new Error("expiration is required");
      }

      if (!params.resourceAbilityRequests) {
        throw new Error("resourceAbilityRequests is required");
      }

      // Create the SIWE message
      const toSign = await createSiweMessageWithRecaps({
        uri: params.uri,
        expiration: params.expiration,
        resources: params.resourceAbilityRequests,
        walletAddress: this.wallet.address,
        nonce: latestBlockhash,
        litNodeClient: this.litNodeClient,
      });

      // Generate the authSig
      const authSig = await generateAuthSig({
        signer: this.wallet,
        toSign,
      });

      return authSig;
    };

    // Define the Lit resource
    const litResource = new LitAccessControlConditionResource("*");

    // Get the session signatures
    const sessionSigs = await this.litNodeClient.getSessionSigs({
      chain: this.chain,
      resourceAbilityRequests: [
        {
          resource: litResource,
          ability: LIT_ABILITY.AccessControlConditionDecryption as LitAbility,
        },
      ],
      authNeededCallback,
      capacityDelegationAuthSig,
    });
    return sessionSigs;
  }

  async decrypt(ciphertext: string, dataToEncryptHash: string, capacityDelegationAuthSig: AuthSig) {
    // Get the session signatures
    const sessionSigs = await this.getSessionSignatures(capacityDelegationAuthSig);

    // Decrypt the message
    const decryptedData = await this.litNodeClient.decrypt({
      accessControlConditions: this.accessControlConditions,
      chain: this.chain,
      ciphertext,
      dataToEncryptHash,
      sessionSigs,
    });

    // Convert Uint8Array to string
    const decryptedString = new TextDecoder().decode(decryptedData.decryptedData);

    // Return the decrypted string
    return { decryptedString };
  }
}

async function main() {
  const chain: Chain = "arbitrum";
  const myLit = new Lit(chain);

  await myLit.connect();

  // const { capacityTokenIdStr, capacityDelegationAuthSig } = await myLit.mintCapacityCredits();
  // console.log("capacityTokenIdStr", capacityTokenIdStr);
  // console.log("capacityDelegationAuthSig", capacityDelegationAuthSig);

  console.log("encrypting...");

  const { ciphertext, dataToEncryptHash } = await myLit.encrypt("Hello, world!");
  console.log("ciphertext:", ciphertext);
  console.log("dataToEncryptHash:", dataToEncryptHash);

  console.log("decrypting...");

  const { decryptedString } = await myLit.decrypt(ciphertext, dataToEncryptHash, capacityDelegationAuthSig);
  console.log("decryptedString:", decryptedString);

  await myLit.disconnect();
}

main().catch((error) => {
  console.error("Error:", error);
  process.exit(1);
});
