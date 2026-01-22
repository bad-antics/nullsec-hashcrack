// ============================================================================
// NullSec HashCrack - Hash Analysis and Identification Tool
// Language: F# (ML-family, .NET platform)
// Author: bad-antics
//
// Security Features:
// - Immutable by default
// - Strong static typing with type inference
// - Pattern matching for safe handling
// - Option types (no nulls)
// - Result types for error handling
// - Pure functions where possible
// ============================================================================

open System
open System.IO
open System.Text.RegularExpressions
open System.Security.Cryptography

let version = "2.0.0"

let banner = """
██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
███████║███████║███████╗███████║██║     ██████╔╝███████║██║     █████╔╝ 
██╔══██║██╔══██║╚════██║██╔══██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
██║  ██║██║  ██║███████║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                  bad-antics • Hash Analysis Tool
═══════════════════════════════════════════════════════════════════════════
"""

// ============================================================================
// Types (Immutable, Discriminated Unions)
// ============================================================================

type HashType =
    | MD5
    | SHA1
    | SHA256
    | SHA384
    | SHA512
    | NTLM
    | MySQL
    | BCrypt
    | Argon2
    | Unknown

type Severity =
    | Critical
    | High
    | Medium
    | Low
    | Info

type HashAnalysis = {
    Hash: string
    HashType: HashType
    Length: int
    IsHex: bool
    Severity: Severity
    Recommendation: string
}

type ValidationError =
    | EmptyInput
    | InvalidCharacters
    | TooLong

type Result<'T, 'E> =
    | Ok of 'T
    | Error of 'E

// ============================================================================
// Validation (Pure Functions)
// ============================================================================

let maxHashLength = 1024

let isHexString (s: string) =
    s |> Seq.forall (fun c -> 
        (c >= '0' && c <= '9') || 
        (c >= 'a' && c <= 'f') || 
        (c >= 'A' && c <= 'F'))

let validateHash (input: string) : Result<string, ValidationError> =
    if String.IsNullOrWhiteSpace(input) then
        Error EmptyInput
    elif input.Length > maxHashLength then
        Error TooLong
    else
        let cleaned = input.Trim().ToLowerInvariant()
        Ok cleaned

// ============================================================================
// Hash Identification (Pattern Matching)
// ============================================================================

let identifyHashType (hash: string) : HashType =
    let len = hash.Length
    let isHex = isHexString hash
    
    match len, isHex with
    | 32, true  -> MD5
    | 40, true  -> SHA1
    | 64, true  -> SHA256
    | 96, true  -> SHA384
    | 128, true -> SHA512
    | 32, false when hash.StartsWith("$NT$") -> NTLM
    | _, false when hash.StartsWith("$2") && hash.Length >= 59 -> BCrypt
    | _, false when hash.StartsWith("$argon2") -> Argon2
    | 16, true  -> MySQL  // Old MySQL
    | 41, _ when hash.StartsWith("*") -> MySQL  // MySQL 5
    | _ -> Unknown

let getSeverity (hashType: HashType) : Severity =
    match hashType with
    | MD5 | SHA1 | MySQL | NTLM -> Critical
    | SHA256 -> Medium
    | SHA384 | SHA512 -> Low
    | BCrypt | Argon2 -> Info
    | Unknown -> High

let getRecommendation (hashType: HashType) : string =
    match hashType with
    | MD5 -> "CRITICAL: MD5 is cryptographically broken. Migrate to bcrypt/argon2 immediately."
    | SHA1 -> "CRITICAL: SHA1 has known collisions. Do not use for security purposes."
    | NTLM -> "CRITICAL: NTLM is weak. Use Kerberos or modern alternatives."
    | MySQL -> "CRITICAL: MySQL old hash is trivially crackable. Upgrade authentication."
    | SHA256 -> "MEDIUM: SHA256 is fast, consider bcrypt/argon2 for passwords."
    | SHA384 | SHA512 -> "LOW: Strong hash, but consider specialized password hashing."
    | BCrypt -> "GOOD: BCrypt is suitable for password hashing."
    | Argon2 -> "EXCELLENT: Argon2 is the recommended password hashing algorithm."
    | Unknown -> "Unable to identify hash type. Manual analysis required."

// ============================================================================
// Analysis Functions
// ============================================================================

let analyzeHash (hash: string) : HashAnalysis =
    let hashType = identifyHashType hash
    {
        Hash = hash
        HashType = hashType
        Length = hash.Length
        IsHex = isHexString hash
        Severity = getSeverity hashType
        Recommendation = getRecommendation hashType
    }

let analyzeFile (filePath: string) : Result<HashAnalysis list, string> =
    try
        if not (File.Exists(filePath)) then
            Error "File not found"
        else
            let analyses =
                File.ReadAllLines(filePath)
                |> Array.filter (fun line -> not (String.IsNullOrWhiteSpace(line)))
                |> Array.map (fun line ->
                    // Handle hash:password or just hash format
                    let hash = 
                        if line.Contains(":") then
                            line.Split(':').[0]
                        else
                            line.Trim()
                    analyzeHash hash)
                |> Array.toList
            Ok analyses
    with
    | ex -> Error ex.Message

// ============================================================================
// Hash Generation (for comparison)
// ============================================================================

let generateMD5 (input: string) : string =
    use md5 = MD5.Create()
    let bytes = System.Text.Encoding.UTF8.GetBytes(input)
    let hash = md5.ComputeHash(bytes)
    BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant()

let generateSHA256 (input: string) : string =
    use sha256 = SHA256.Create()
    let bytes = System.Text.Encoding.UTF8.GetBytes(input)
    let hash = sha256.ComputeHash(bytes)
    BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant()

let generateSHA512 (input: string) : string =
    use sha512 = SHA512.Create()
    let bytes = System.Text.Encoding.UTF8.GetBytes(input)
    let hash = sha512.ComputeHash(bytes)
    BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant()

// ============================================================================
// Output Formatting
// ============================================================================

let severityColor (severity: Severity) =
    match severity with
    | Critical -> ConsoleColor.Red
    | High -> ConsoleColor.DarkRed
    | Medium -> ConsoleColor.Yellow
    | Low -> ConsoleColor.Cyan
    | Info -> ConsoleColor.Green

let printColored (color: ConsoleColor) (text: string) =
    let original = Console.ForegroundColor
    Console.ForegroundColor <- color
    printf "%s" text
    Console.ForegroundColor <- original

let printHeader (text: string) =
    printColored ConsoleColor.Cyan (sprintf "\n[*] %s\n" text)

let printSuccess (text: string) =
    printColored ConsoleColor.Green (sprintf "[✓] %s\n" text)

let printError (text: string) =
    printColored ConsoleColor.Red (sprintf "[✗] %s\n" text)

let printAnalysis (analysis: HashAnalysis) =
    let severityStr = 
        match analysis.Severity with
        | Critical -> "CRITICAL"
        | High -> "HIGH"
        | Medium -> "MEDIUM"
        | Low -> "LOW"
        | Info -> "INFO"
    
    let hashTypeStr =
        match analysis.HashType with
        | MD5 -> "MD5"
        | SHA1 -> "SHA1"
        | SHA256 -> "SHA256"
        | SHA384 -> "SHA384"
        | SHA512 -> "SHA512"
        | NTLM -> "NTLM"
        | MySQL -> "MySQL"
        | BCrypt -> "BCrypt"
        | Argon2 -> "Argon2"
        | Unknown -> "Unknown"
    
    printfn ""
    printColored (severityColor analysis.Severity) (sprintf "  [%s] " severityStr)
    printfn "%s" hashTypeStr
    printfn "    Hash:   %s" (if analysis.Hash.Length > 60 then analysis.Hash.Substring(0, 57) + "..." else analysis.Hash)
    printfn "    Length: %d characters" analysis.Length
    printfn "    Hex:    %b" analysis.IsHex
    printfn "    %s" analysis.Recommendation

let printStats (analyses: HashAnalysis list) =
    let critical = analyses |> List.filter (fun a -> a.Severity = Critical) |> List.length
    let high = analyses |> List.filter (fun a -> a.Severity = High) |> List.length
    let medium = analyses |> List.filter (fun a -> a.Severity = Medium) |> List.length
    
    printHeader "Analysis Statistics"
    printfn "  Total Hashes:    %d" analyses.Length
    printfn "  Critical:        %d" critical
    printfn "  High:            %d" high
    printfn "  Medium:          %d" medium

// ============================================================================
// Main Entry Point
// ============================================================================

[<EntryPoint>]
let main argv =
    printColored ConsoleColor.Red banner
    printfn ""
    
    if argv.Length = 0 then
        printError "Usage: nullsec-hashcrack <hash|file>"
        printfn "\nOptions:"
        printfn "  <hash>     Single hash to analyze"
        printfn "  <file>     File containing hashes (one per line)"
        printfn "  --version  Show version"
        printfn "  --help     Show this help"
        printfn "\nExamples:"
        printfn "  nullsec-hashcrack 5f4dcc3b5aa765d61d8327deb882cf99"
        printfn "  nullsec-hashcrack hashes.txt"
        1
    elif argv.[0] = "--version" then
        printfn "NullSec HashCrack v%s" version
        0
    elif argv.[0] = "--help" then
        printfn "NullSec HashCrack - Hash Analysis and Identification Tool"
        printfn "\nIdentifies hash types and provides security recommendations."
        printfn "\nSupported hash types:"
        printfn "  MD5, SHA1, SHA256, SHA384, SHA512"
        printfn "  NTLM, MySQL, BCrypt, Argon2"
        0
    elif File.Exists(argv.[0]) then
        // Analyze file
        printHeader (sprintf "Analyzing file: %s" argv.[0])
        
        match analyzeFile argv.[0] with
        | Ok analyses ->
            printStats analyses
            printHeader "Hash Analysis"
            analyses |> List.iter printAnalysis
            
            let criticalCount = analyses |> List.filter (fun a -> a.Severity = Critical) |> List.length
            printfn ""
            if criticalCount > 0 then
                printError (sprintf "Found %d critically weak hashes!" criticalCount)
                1
            else
                printSuccess "No critically weak hashes found"
                0
        | Error msg ->
            printError msg
            1
    else
        // Analyze single hash
        match validateHash argv.[0] with
        | Ok hash ->
            let analysis = analyzeHash hash
            printHeader "Hash Analysis"
            printAnalysis analysis
            printfn ""
            if analysis.Severity = Critical then
                printError "This hash uses a critically weak algorithm!"
                1
            else
                printSuccess "Analysis complete"
                0
        | Error EmptyInput ->
            printError "Empty input"
            1
        | Error InvalidCharacters ->
            printError "Invalid characters in input"
            1
        | Error TooLong ->
            printError "Input too long"
            1
