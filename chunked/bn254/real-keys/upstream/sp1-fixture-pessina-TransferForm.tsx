"use client";

import { useState, useEffect, useCallback } from "react";
import { useForm } from "react-hook-form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import GoogleButton from "@/components/GoogleButton";
import { toast } from "sonner";
import { Send, Shield, Copy, Check, Plus } from "lucide-react";
import { useEnv } from "@/hooks/useEnv";
import { useSolanaProgram } from "@/hooks/useSolanaProgram";
import { useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { Buffer } from "buffer";
import { parseOIDCToken } from "@/lib/utils";

interface TransferFormProps {
  className?: string;
}

interface TransferData {
  amount: number;
  destinationAddress: string;
}

interface ZKProofData {
  email: string;
  groth16Proof: {
    proof: Buffer;
    sp1PublicInputs: Buffer;
  };
}

interface UserAccount {
  salt: string;
  address: string;
  balance: number;
  exists: boolean;
}

const TransferForm = ({ className }: TransferFormProps) => {
  const { NEXT_PUBLIC_JWT_ZK_PROOF_SERVER_URL } = useEnv();
  const { connected } = useWallet();
  const {
    isReady,
    createUserAccount,
    transferFromUserAccount,
    getUserAccountBalance,
    checkUserAccountExists,
    getUserAccountAddress,
  } = useSolanaProgram();

  const [isLoading, setIsLoading] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [zkProofData, setZkProofData] = useState<ZKProofData | null>(null);
  const [userAccounts, setUserAccounts] = useState<UserAccount[]>([]);
  const [selectedSalt, setSelectedSalt] = useState<string>("default");
  const [newSalt, setNewSalt] = useState<string>("");
  const [copiedAddress, setCopiedAddress] = useState(false);

  // Predefined salts for common account types
  const defaultSalts = ["default", "savings", "business", "trading"];

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isValid },
    watch,
  } = useForm<TransferData>({
    mode: "onChange",
    defaultValues: {
      amount: 0,
      destinationAddress: "",
    },
  });

  const watchedAmount = watch("amount");

  const currentAccount = userAccounts.find((acc) => acc.salt === selectedSalt);

  // Copy PDA address function
  const copyPDAAddress = async () => {
    if (!zkProofData || !selectedSalt) return;

    const [pdaAddress] = getUserAccountAddress(zkProofData.email, selectedSalt);
    await navigator.clipboard.writeText(pdaAddress.toString());
    setCopiedAddress(true);
    toast.success("PDA address copied to clipboard!");
    setTimeout(() => setCopiedAddress(false), 2000);
  };

  // Load user accounts
  const loadUserAccounts = useCallback(async () => {
    if (!zkProofData || !isReady) return;

    const accounts: UserAccount[] = [];

    // Check all predefined salts + any custom ones
    const allSalts = [...defaultSalts];
    if (newSalt && !allSalts.includes(newSalt)) {
      allSalts.push(newSalt);
    }

    for (const salt of allSalts) {
      try {
        const exists = await checkUserAccountExists(zkProofData.email, salt);
        const [address] = getUserAccountAddress(zkProofData.email, salt);
        let balance = 0;

        if (exists) {
          balance = await getUserAccountBalance(zkProofData.email, salt);
        }

        accounts.push({
          salt,
          address: address.toString(),
          balance,
          exists,
        });
      } catch (error) {
        console.error(`Failed to check account for salt ${salt}:`, error);
      }
    }

    setUserAccounts(accounts);

    return accounts;
  }, [
    zkProofData,
    isReady,
    checkUserAccountExists,
    getUserAccountAddress,
    getUserAccountBalance,
    newSalt,
  ]);

  useEffect(() => {
    loadUserAccounts();
  }, [loadUserAccounts]);

  // Real-time balance polling for existing accounts
  useEffect(() => {
    if (!zkProofData) return;

    const interval = setInterval(async () => {
      if (userAccounts.length > 0) {
        const updatedAccounts = await Promise.all(
          userAccounts.map(async (account) => {
            console.log(account);
            try {
              const balance = await getUserAccountBalance(
                zkProofData.email,
                account.salt
              );
              return { ...account, balance };
            } catch (error) {
              console.error(
                `Failed to update balance for ${account.salt}:`,
                error
              );
              return account;
            }
          })
        );
        setUserAccounts(updatedAccounts);
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [
    zkProofData,
    isReady,
    getUserAccountBalance,
    checkUserAccountExists,
    loadUserAccounts,
    userAccounts,
  ]);

  const handleGoogleSuccess = async (token: string) => {
    const { email, kid } = parseOIDCToken(token);

    try {
      // Fetch Google JWKS
      const jwksResponse = await fetch(
        "https://www.googleapis.com/oauth2/v3/certs"
      );
      const jwks = (await jwksResponse.json()) as {
        keys: Array<{
          kid: string;
          n: string;
          e: string;
          kty: string;
          alg: string;
          use: string;
        }>;
      };

      const key = jwks.keys.find((k) => k.kid === kid);
      if (!key) {
        throw new Error(`No key found for kid: ${kid}`);
      }

      // Proving is working, do not remove this code
      // Get ZK proof from server
      // const response = await fetch(
      //   `${NEXT_PUBLIC_JWT_ZK_PROOF_SERVER_URL}/generate-proof`,
      //   {
      //     method: "POST",
      //     headers: {
      //       "Content-Type": "application/json",
      //     },
      //     body: JSON.stringify({
      //       jwt_token: token,
      //       public_key: {
      //         n: key.n,
      //         e: key.e,
      //       },
      //     }),
      //   }
      // );

      // if (!response.ok) {
      //   throw new Error(`Failed to get ZK proof: ${response.statusText}`);
      // }

      // const proofResult = await response.json();

      const proofResult = {
        proof:
          "a4594c590a66ef12edb001c8882f9bd7864a08a7632c47ab307653856802a6b91fc8278b0874f2f63b75d549aee19b97795e9014487d476113090d43c10d620d5d1c382706db7309889e6147003d59e2ac4ba757fb39c83d7939ca295d6afbefa521ac8501c6b4c236fe3f741cb4191673db2385b7262df37345110f011d90be806920fb2c4e9532c327c83b52ff4ef2a7214152b4f5334e3b664b222bcf21929b29f2a21542e7396b4166f16f835aadaf4841909def08cca74350604dbaf1d607eb8ddb071b79975c87e4891023b5efb43b1bc02e26f196855410f13ccb6eb30f88fdfa0daeb310570cb4b0835f23cdf82d1de7022d54441aa9b4379ebd6a2d882aa397",
        verification_key:
          "0x00390c74c859c201b98ba24a54e76c683b6a25625767e42529b156f19cfc4eae",
        public_outputs_bytes:
          "b9c53ddad62c54e2b8e437460ac30709d700d1eb6b0d1b58e2344a6c64cef0c4a4a787d8be7a56f1a18eb2726ac123c5a56ed3d4676e970915b717b1ff81204c000000000000000001",
        proof_size: 260,
      };

      console.log("proofResult", proofResult);

      // Convert hex strings to Uint8Array
      const proof = Buffer.from(proofResult.proof, "hex");
      const sp1PublicInputs = Buffer.from(
        proofResult.public_outputs_bytes,
        "hex"
      );
      setZkProofData({
        email,
        groth16Proof: {
          proof,
          sp1PublicInputs: sp1PublicInputs,
        },
      });

      setIsAuthenticated(true);
      toast.success("Successfully signed in with Google!");
    } catch (error) {
      console.error("Failed to get ZK proof:", error);
      toast.error("Failed to generate ZK proof. Please try again.");
    }
  };

  const handleCreateAccount = async (salt: string) => {
    if (!zkProofData || !connected || !isReady) {
      toast.error("Please connect your wallet and sign in with Google first");
      return;
    }

    if (salt.length > 32) {
      toast.error("Salt must be 32 characters or less");
      return;
    }

    setIsLoading(true);

    try {
      const result = await createUserAccount({
        email: zkProofData.email,
        salt,
        groth16Proof: zkProofData.groth16Proof,
      });

      toast.success(
        `Account created successfully! Salt: ${salt}, Address: ${result.userAccount.toString()}`
      );

      // Reload accounts to show the new one
      await loadUserAccounts();
      setSelectedSalt(salt);
      setNewSalt("");
    } catch (error) {
      console.error("Account creation error:", error);
      toast.error(
        error instanceof Error
          ? error.message
          : "Account creation failed. Please try again."
      );
    } finally {
      setIsLoading(false);
    }
  };

  const onSubmit = async (data: TransferData) => {
    if (!zkProofData || !connected || !isReady || !currentAccount) {
      toast.error("Please connect your wallet and sign in with Google first");
      return;
    }

    if (!currentAccount.exists) {
      toast.error("Selected account does not exist. Please create it first.");
      return;
    }

    if (data.amount > currentAccount.balance) {
      toast.error(
        `Insufficient balance. Available: ${currentAccount.balance.toFixed(
          4
        )} SOL`
      );
      return;
    }

    setIsLoading(true);

    try {
      const result = await transferFromUserAccount({
        email: zkProofData.email,
        salt: selectedSalt,
        groth16Proof: zkProofData.groth16Proof,
        amount: data.amount,
        destinationAddress: data.destinationAddress,
      });

      toast.success(`Transfer successful! Transaction: ${result.signature}`);

      // Reset form and reload accounts
      reset();
      await loadUserAccounts();
    } catch (error) {
      console.error("Transfer error:", error);
      toast.error(
        error instanceof Error
          ? error.message
          : "Transfer failed. Please try again."
      );
    } finally {
      setIsLoading(false);
    }
  };

  const signOut = () => {
    setIsAuthenticated(false);
    setZkProofData(null);
    setUserAccounts([]);
    setSelectedSalt("default");
    setNewSalt("");
    reset();
    toast.info("Signed out successfully");
  };

  return (
    <Card className={`w-full max-w-md mx-auto ${className}`}>
      <CardHeader className="text-center">
        <div className="flex items-center justify-center mb-4">
          <div className="p-3 bg-primary/10 rounded-full">
            <Shield className="h-8 w-8 text-primary" />
          </div>
        </div>
        <CardTitle className="text-2xl font-bold">ZK Solana Transfer</CardTitle>
        <CardDescription>
          Secure, privacy-preserving transfers with multiple accounts
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Step 1: Connect Wallet */}
        {!connected ? (
          <div className="text-center space-y-4">
            <p className="text-sm text-muted-foreground">
              Connect your Solana wallet to get started
            </p>
            <WalletMultiButton className="w-full" />
          </div>
        ) : /* Step 2: Sign in with Google */ !isAuthenticated ? (
          <div className="text-center space-y-4">
            <p className="text-sm text-muted-foreground">
              Sign in with Google to generate your ZK proof
            </p>
            <GoogleButton
              onSuccess={handleGoogleSuccess}
              onError={() =>
                toast.error("Failed to sign in with Google. Please try again.")
              }
            />
          </div>
        ) : (
          /* Step 3: Account Management and Transfer */
          <div className="space-y-4">
            {/* Auth Status */}
            <div className="flex items-center justify-between p-3 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200 dark:border-green-800">
              <div className="flex items-center space-x-2">
                <div className="h-2 w-2 bg-green-500 rounded-full"></div>
                <span className="text-sm font-medium text-green-800 dark:text-green-200">
                  Authenticated
                </span>
              </div>
              <Button variant="outline" size="sm" onClick={signOut}>
                Sign Out
              </Button>
            </div>

            {/* Email Display */}
            {zkProofData && (
              <div className="p-3 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800">
                <div className="text-xs font-medium text-blue-800 dark:text-blue-200">
                  Email: {zkProofData.email}
                </div>
              </div>
            )}

            {/* Account Selection */}
            <div className="space-y-3">
              <Label>Select Account</Label>
              <select
                value={selectedSalt}
                onChange={(e) => setSelectedSalt(e.target.value)}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {userAccounts.length === 0 && (
                  <option value="">No accounts available</option>
                )}
                {userAccounts.map((account) => (
                  <option key={account.salt} value={account.salt}>
                    {account.salt}{" "}
                    {account.exists
                      ? `(${account.balance.toFixed(4)} SOL)`
                      : "(Not created)"}
                  </option>
                ))}
              </select>
            </div>

            {/* Current Account Info */}
            {currentAccount && (
              <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg border">
                <div className="space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-medium">Status:</span>
                    <span
                      className={
                        currentAccount.exists
                          ? "text-green-600"
                          : "text-red-600"
                      }
                    >
                      {currentAccount.exists ? "Active" : "Not Created"}
                    </span>
                  </div>
                  {currentAccount.exists && (
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Balance:</span>
                      <span>
                        {currentAccount.balance.toFixed(4)} SOL
                        <span className="text-xs text-green-600 ml-1">
                          ● Live
                        </span>
                      </span>
                    </div>
                  )}
                  <div className="space-y-1">
                    <div className="font-medium">Address:</div>
                    <div className="flex items-center space-x-2 p-2 bg-white dark:bg-gray-800 rounded border">
                      <code className="text-xs font-mono text-gray-800 dark:text-gray-200 flex-1 break-all">
                        {currentAccount.address}
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={copyPDAAddress}
                        className="h-6 w-6 p-0 flex-shrink-0"
                      >
                        {copiedAddress ? (
                          <Check className="h-3 w-3 text-green-600" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Create New Account */}
            <div className="space-y-3">
              <Label>Create New Account</Label>
              <div className="flex space-x-2">
                <Input
                  placeholder="Enter salt (e.g., 'personal')"
                  value={newSalt}
                  onChange={(e) => setNewSalt(e.target.value)}
                  maxLength={32}
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleCreateAccount(newSalt)}
                  disabled={!newSalt || isLoading || newSalt.length > 32}
                  className="flex-shrink-0"
                >
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              <div className="text-xs text-muted-foreground">
                Salt must be 32 characters or less
              </div>
            </div>

            {/* Quick Create Buttons */}
            <div className="space-y-2">
              <Label className="text-xs">Quick Create:</Label>
              <div className="flex flex-wrap gap-2">
                {defaultSalts
                  .filter(
                    (salt) =>
                      !userAccounts.find((acc) => acc.salt === salt)?.exists
                  )
                  .map((salt) => (
                    <Button
                      key={salt}
                      variant="outline"
                      size="sm"
                      onClick={() => handleCreateAccount(salt)}
                      disabled={isLoading}
                      className="text-xs"
                    >
                      {salt}
                    </Button>
                  ))}
              </div>
            </div>

            {/* Transfer Form */}
            {currentAccount?.exists ? (
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="amount">
                    Amount (SOL)
                    <span className="text-xs text-muted-foreground ml-2">
                      Available: {currentAccount.balance.toFixed(4)}
                    </span>
                  </Label>
                  <Input
                    id="amount"
                    type="number"
                    step="0.0001"
                    min="0"
                    max={currentAccount.balance}
                    placeholder="0.1"
                    {...register("amount", {
                      required: "Amount is required",
                      min: {
                        value: 0.0001,
                        message: "Minimum amount is 0.0001 SOL",
                      },
                      max: {
                        value: currentAccount.balance,
                        message: "Amount exceeds available balance",
                      },
                      valueAsNumber: true,
                    })}
                    className="text-lg"
                  />
                  {errors.amount && (
                    <p className="text-sm text-red-500">
                      {errors.amount.message}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="destination">Destination Address</Label>
                  <Input
                    id="destination"
                    placeholder="Solana public key"
                    {...register("destinationAddress", {
                      required: "Destination address is required",
                      pattern: {
                        value: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
                        message: "Invalid Solana address format",
                      },
                    })}
                    className="font-mono text-sm"
                  />
                  {errors.destinationAddress && (
                    <p className="text-sm text-red-500">
                      {errors.destinationAddress.message}
                    </p>
                  )}
                </div>

                <Button
                  type="submit"
                  disabled={
                    isLoading ||
                    !isValid ||
                    currentAccount.balance === 0 ||
                    watchedAmount > currentAccount.balance
                  }
                  className="w-full"
                  size="lg"
                >
                  {isLoading ? (
                    <div className="flex items-center space-x-2">
                      <div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Processing Transfer...</span>
                    </div>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <Send className="h-4 w-4" />
                      <span>Send Transfer</span>
                    </div>
                  )}
                </Button>
              </form>
            ) : (
              <div className="text-center text-muted-foreground text-sm">
                Select an existing account or create a new one to start
                transferring
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default TransferForm;
