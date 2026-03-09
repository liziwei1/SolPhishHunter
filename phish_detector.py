import csv
import json
import logging
import os
import pickle
import re
from typing import Counter
import pandas as pd
from tqdm import tqdm
from sol_class import solInstruction, solChange, tokenChange, solTransaction
import time
import datetime

# Initialize global lists
markets = []
system_accounts = []
safe_accounts = []

# Keywords related to market transactions (buy/sell/swap/purchase in all tenses)
market_keywords = [
    # sell
    "sell",        # base form
    "sells",       # 3rd person singular
    "selling",     # present participle/gerund
    "sold",        # past tense
    "sold",        # past participle
    
    # buy
    "buy",         # base form
    "buys",        # 3rd person singular
    "buying",      # present participle/gerund
    "bought",      # past tense
    "bought",      # past participle
    
    # swap
    "swap",        # base form
    "swaps",       # 3rd person singular
    "swapping",    # present participle/gerund
    "swapped",     # past tense
    "swapped",     # past participle
    
    # purchase
    "purchase",    # base form
    "purchases",   # 3rd person singular
    "purchasing",  # present participle/gerund
    "purchased",   # past tense
    "purchased"    # past participle
]

def check_log(log):
    """Check if log contains market-related keywords"""
    for keyword in market_keywords:
        if keyword in log:
            return True
    return False

def update_info(s):
    """Clean and format string for JSON parsing"""
    s = s.replace('None', "''")
    return re.sub(r"'", '"', s)

def get_dataset(data_path):
    '''
    Read CSV files to construct a dataset of solTransaction objects
    @param data_path: Path containing all CSV files of the dataset
    @return: List of solTransaction objects
    '''
    dataset_path = f'{data_path}/sol_dataset.pkl'
    
    # Load pre-saved dataset if exists
    if os.path.exists(dataset_path):
        print("Great! It's a ready-made dataset, we're saved!")
        with open(dataset_path,'rb') as f:
            dataset = pickle.load(f)
            return dataset
    else:
        # Read all required CSV files
        trans_data = pd.read_csv(f'{data_path}/Transactions.csv', encoding='ISO-8859-1')
        log_data = pd.read_csv(f'{data_path}/Log.csv', encoding='ISO-8859-1')
        solchange_data = pd.read_csv(f'{data_path}/SOLBalanceChange.csv', encoding='ISO-8859-1')
        tokenchange_data = pd.read_csv(f'{data_path}/TokenBalanceChange.csv', encoding='ISO-8859-1')
        ins_data = pd.read_csv(f'{data_path}/Instruction.csv', encoding='ISO-8859-1')

        # Build solTransaction objects
        sol_dataset = []
        for index, row in tqdm(trans_data.iterrows(), total=trans_data.shape[0]):
            try:
                # Print progress every 100 iterations
                if index % 100 == 0:
                    print(datetime.datetime.now(), index)

                # Extract transaction basic info
                sig = row['signature']
                block_time = row['blocktime']
                block_hash = row['recent_blockhash']
                
                # Get transaction log
                log_rows = log_data[log_data['signature'] == sig]
                log = str(log_rows.iloc[0]['log'])

                # Parse instructions
                instructions = []
                ins_rows = ins_data[ins_data['signature'] == sig]
                for idx, ins_row in ins_rows.iterrows():
                    instructions.append(solInstruction(
                        sig, 
                        ins_row['trace_id'], 
                        ins_row['type'], 
                        ins_row['info'], 
                        ins_row['program'], 
                        ins_row['program_id'], 
                        ins_row['accounts']
                    ))
                
                # Parse SOL balance changes
                sol_changes = []
                solchange_rows = solchange_data[solchange_data['signature'] == sig]
                for idx, solchange_row in solchange_rows.iterrows():
                    sol_changes.append(solChange(
                        sig, 
                        solchange_row['Address'], 
                        solchange_row['Balance_Before'], 
                        solchange_row['Balance_After'], 
                        solchange_row['Change']
                    ))
                
                # Parse Token balance changes
                token_changes = []
                tokenchange_rows = tokenchange_data[tokenchange_data['signature'] == sig]
                for idx, tokenchange_row in tokenchange_rows.iterrows():
                    token_changes.append(tokenChange(
                        sig, 
                        tokenchange_row['Address'], 
                        tokenchange_row['Owner'], 
                        tokenchange_row['Balance_Before'], 
                        tokenchange_row['Balance_After'], 
                        tokenchange_row['Change'], 
                        tokenchange_row['Token']
                    ))

                # Create solTransaction object
                tran = solTransaction(
                    signature = sig,
                    block_time = block_time,
                    recent_blockhash = block_hash,
                    instructions = instructions,
                    sol_balance_change = sol_changes,
                    token_balance_change = token_changes,
                    log = log
                )
                sol_dataset.append(tran)
                
            except Exception as e:
                # Skip rows with parsing errors
                continue

        print(f"Total valid transactions: {len(sol_dataset)}")
        
        # Save dataset for future use
        with open(dataset_path, 'wb') as f:
            pickle.dump(sol_dataset, f)
            
        return sol_dataset

def phish_detect(tran: solTransaction):
    """
    Detect SolPhish attacks and classify attack types
    Returns: (attack_type_code, victims_list, phishers_list, token_accounts_list, loss_list)
    Attack type codes:
    - 10000: Type I (Multiple Transfers in Single Transaction)
    - 1000: Type II.1 (Account Ownership Transfer via Assign)
    - 100: Type II.2 (Token Account Hijack via SetAuthority)
    - 10: Type III (Impersonation of System Accounts)
    - 1: Additional flag for Durable Nonce usage
    - 0: No phishing detected
    """
    phish_type = 0

    # Instruction counters and data collectors
    transfer_num = 0
    nonce_num = 0
    authority_num = 0
    new_authority = []
    old_authority = []
    new_assign = []
    old_assign = []
    new_stake = []
    old_stake = []
    programs = []
    all_token_account = []
    token_account1 = []
    token_account2 = []
    assign_num = 0
    stake_num = 0

    # Analyze each instruction in the transaction
    for ins in tran.instructions:
        if ins.type == 'transfer':
            transfer_num += 1
        elif ins.type == 'advanceNonce':
            nonce_num += 1
        elif ins.type == 'setAuthority':
            # Parse setAuthority instruction details
            info = update_info(ins.info)
            info = json.loads(info)
            if info.get('authorityType', '') == 'accountOwner':
                authority_num += 1
                new_authority.append(info.get('newAuthority'))
                old_authority.append(info.get('authority'))
                token_account2.append(info.get('account'))
        elif ins.type == 'assign':
            # Parse assign instruction details
            info = update_info(ins.info)
            info = json.loads(info)
            if info.get('owner') != '11111111111111111111111111111111':
                new_assign.append(info.get('owner'))
                old_assign.append(info.get('account'))
                assign_num += 1
        elif ins.type == 'authorize':
            # Parse authorize instruction details
            info = update_info(ins.info)
            info = json.loads(info)
            new_stake.append(info.get('newAuthority'))
            old_stake.append(info.get('authority'))
            stake_num += 1
        elif ins.type == 'createAccount':
            # Incomplete code placeholder - left as original
            pass

        # If transaction interacts with market programs, not phishing
        if ins.program_id in markets:
            return 0, [], [], [], []

    # Analyze token balance changes (identify drained accounts)
    token_all_in_accounts = []  # Accounts with all tokens drained
    token_win_accounts = []     # Accounts that received tokens
    seen_addresses1 = set()
    
    for token_change in tran.token_balance_change:
        if token_change.address not in seen_addresses1:
            seen_addresses1.add(token_change.address)
            
            # Account was completely drained of tokens
            if token_change.balance_before != 0 and token_change.balance_after == 0:
                token_all_in_accounts.append(token_change.owner)
                token_account1.append(token_change.address)
            # Account received tokens (potential phisher)
            elif token_change.change > 0:
                token_win_accounts.append(token_change.owner)
    
    # Count how many different tokens were drained from each account
    account_counts = Counter(token_all_in_accounts)

    # Analyze SOL balance changes (identify drained accounts)
    sol_all_in_accounts = []    # Accounts with all SOL drained
    sol_win_accounts = []       # Accounts that received SOL
    seen_addresses2 = set()
    
    for sol_change in tran.sol_balance_change:
        if sol_change.address not in seen_addresses2:
            seen_addresses2.add(sol_change.address)
            
            # Account was completely drained of SOL
            if sol_change.balance_before != 0 and sol_change.balance_after == 0:
                sol_all_in_accounts.append(sol_change.address)
            # Account received SOL (potential phisher)
            elif sol_change.change > 0 and sol_change.address != '11111111111111111111111111111111':
                sol_win_accounts.append(sol_change.address)

    # Initialize victim and phisher lists
    victims = []
    phishers = []

    # Detect Type I: Multiple Transfers in Single Transaction
    # Criteria: >=3 transfer instructions + at least 2 different tokens drained + no market keywords in log
    if transfer_num >=3 and not check_log(tran.log):
        victims1 = [account for account, count in account_counts.items() if count > 1]
        if victims1:
            # Exclude safe accounts from phisher list
            for phisher in token_win_accounts:
                if phisher in safe_accounts:
                    return 0, [], [], [], []
            
            victims += victims1
            phishers += token_win_accounts
            phish_type += 10000  # Type I identifier
            all_token_account += token_account1
    
    # Detect Type II.1: Account Ownership Transfer via Assign instruction
    if assign_num != 0 and not check_log(tran.log):
        # Exclude safe accounts
        for account in new_assign + old_assign:
            if account in safe_accounts:
                return 0, [], [], [], []      

        victims += old_assign
        phishers += new_assign
        phish_type += 1000  # Type II.1 identifier

    # Detect Type II.2: Token Account Hijack via SetAuthority instruction
    if authority_num != 0 and not check_log(tran.log):
        if old_authority != new_authority:
            # Exclude safe accounts
            for account in new_authority + old_authority:
                if account in safe_accounts:
                    return 0, [], [], [], []
            
            phishers += new_authority
            victims += old_authority
            phish_type += 100  # Type II.2 identifier
            all_token_account += token_account2

    # Detect Type III: Impersonation of System Accounts
    # Criteria: Drained token/SOL accounts + phisher addresses mimic official accounts
    if token_all_in_accounts or sol_all_in_accounts:
        phishers2 = []
        # Check for addresses mimicking official accounts (ending with 1111 or starting with Comp)
        for phisher in token_win_accounts + sol_win_accounts:
            if isinstance(phisher, str) and (phisher.endswith('1111') or phisher.startswith('Comp')) and phisher not in safe_accounts:
                phishers2.append(phisher)
        
        if len(phishers2):
            victims2 = token_all_in_accounts + sol_all_in_accounts
            victims += victims2
            phishers += phishers2
            phish_type += 10  # Type III identifier
            all_token_account += token_account1

    # Additional flag: Durable Nonce usage
    if nonce_num != 0 and phish_type != 0:
        phish_type += 1

    # Remove duplicates and None values
    victims = list(set(victim for victim in victims if victim is not None))
    phishers = list(set(phisher for phisher in phishers if phisher is not None))
    
    # If victims and phishers are the same, not a phishing attack
    if set(victims) == set(phishers):
        return 0, [], [], [], []
    
    # Calculate financial losses
    loss = []
    # Token losses
    for tb in tran.token_balance_change:
        if tb.owner in victims or tb.address in all_token_account:
            loss.append((tb.token, tb.balance_before))
    # SOL losses
    for sb in tran.sol_balance_change:
        if sb.address in victims and sb.change < 0:
            loss.append(('sol', abs(sb.change)))  

    return phish_type, victims, phishers, all_token_account, loss

# --------------------------
# Main Execution
# --------------------------

# Load market program addresses
market_path = 'SolPhishHunter/Authority_label/label_market.csv'
with open(market_path, mode='r', newline='', encoding='utf-8') as file:
    reader = csv.DictReader(file)
    for row in reader:
        address = row.get('address') 
        markets.append(address)
    print(f"Loaded {len(markets)} market program addresses")

# Load system account addresses
system_path = 'SolPhishHunter/Authority_label/system_accounts.csv'
with open(system_path, mode='r', newline='', encoding='utf-8') as file:
    reader = csv.DictReader(file)
    for row in reader:
        address = row.get('address') 
        system_accounts.append(address)
    print(f"Loaded {len(system_accounts)} system account addresses")

# Create safe accounts whitelist (markets + system accounts)
safe_accounts = markets + system_accounts

# Load transaction dataset
# data_path = 'SolPhishHunter/phish_accounts'  # Phishing transactions path
data_path = 'SolPhishHunter/normal_accounts'    # Normal transactions path
dataset = get_dataset(data_path)

# Generate phishing detection results
with open(f'{data_path}/RESULTS.csv', 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    # Write header row
    writer.writerow(['index','signature', 'time', 'phish_type', 'victims', 'phishers', 'token_accounts', 'loss'])
    
    # Process each transaction
    for index, data in enumerate(dataset):
        phish_type, victims, phishers, token_accounts, loss = phish_detect(data)
        
        # Only record detected phishing transactions
        if phish_type != 0:
            writer.writerow([
                index, 
                data.signature, 
                data.block_time, 
                phish_type, 
                ','.join(victims), 
                ','.join(phishers), 
                ','.join(token_accounts), 
                str(loss)
            ])
    
    print("Phishing detection completed! Results saved to RESULTS.csv")

# --------------------------
# Validation against labeled phisher addresses
# --------------------------

# Read detection results and labeled phisher addresses
phishers_df = pd.read_csv(f'{data_path}/RESULTS.csv')
addresses_df = pd.read_csv(f'SolPhishHunter/Authority_label/addresses.csv')

# Convert labeled phisher addresses to list
label_phishers_list = addresses_df['address'].tolist()

def check_phishers(phishers_str, label_phishers_list):
    """
    Check if detected phishers match labeled phisher addresses
    Returns:
    - type_result: 1 (all phishers are labeled), 0 (partial match), -1 (no match)
    - common: list of matching addresses
    """
    phishers_list = phishers_str.split(',')
    # Find intersection between detected and labeled phishers
    common = list(set(phishers_list) & set(label_phishers_list))
    
    if common:
        if set(phishers_list).issubset(set(label_phishers_list)):
            return 1, common  # All detected phishers are labeled
        else:
            return 0, common  # Partial match
    else:
        return -1, []  # No match

# Process each row to validate phishers
results = []
for index, row in phishers_df.iterrows():
    phishers = row['phishers']
    victims = row['victims'].split(',')  # Split multiple victims
    
    type_result = -1
    label_phishers_result = []
    is_victim_label_phisher = False
    
    # Check if any victim is in labeled phisher list
    for victim in victims:
        if victim in label_phishers_list:
            is_victim_label_phisher = True
            break
    
    # Check phisher matches
    type_result, label_phishers_result = check_phishers(phishers, label_phishers_list)
    
    # Combine original data with validation results
    new_row = row.to_dict()
    new_row['label_phisher'] = label_phishers_result
    new_row['type'] = type_result
    new_row['is_victim_label_phisher'] = is_victim_label_phisher
    results.append(new_row)

# Create new DataFrame and save validation results
new_df = pd.DataFrame(results)
new_df.to_csv(rf'{data_path}/results.csv', index=False)

print("Validation against labeled phishers completed! Results saved to results.csv")