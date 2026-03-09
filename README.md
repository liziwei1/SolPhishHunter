# SolPhishHunter

This repository contains the implementation and dataset for the paper **"SolPhishHunter: Toward Detecting and Understanding Phishing on Solana"** published in IEEE Transactions on Information Forensics and Security (TIFS) 2026.

## Overview

Solana is a rapidly evolving blockchain platform that has attracted an increasing number of users. However, this growth has also drawn the attention of malicious actors, with some phishers extending their reach into the Solana ecosystem. Unlike platforms such as Ethereum, Solana has distinct designs of accounts and transactions, leading to the emergence of new types of phishing transactions that we term **SolPhish**.

## Repository Contents

- **Detection Code**: Key implementation of the SolPhishHunter detection tool
- **Dataset**: SolPhishDataset - the first Solana phishing-related dataset in academia, containing 8,058 detected SolPhish instances

## SolPhish Types

We define **three types** of SolPhish attacks:

1. **Type I**: Single Transaction with Multiple Transfers (STMT) – Leveraging Solana's unique transaction design that allows multiple instructions within a single transaction, phishers embed multiple transfer instructions to plunder multiple types of tokens and SOL from victims' wallets in one malicious transaction, eliminating the need for separate transfers for each token as required on platforms like Ethereum.
  
2. **Type II**: Account Authority Transfer (AAT) – Exploiting Solana's account permission mechanism, phishers induce victims to sign transactions containing Assign or SetAuthority instructions. The Assign instruction reassigns the owner of a wallet account to a malicious program, while the SetAuthority instruction designates phishers as the owner of target token accounts, enabling direct control of victims' assets; both types of authority transfers may occur in the same transaction.
 
3. **Type III**: Impersonation of System Accounts (ISA) – Phishers use tools like `solana-keygen grind` or SlerfTools to generate vanity addresses with prefixes (e.g., "Compu") or suffixes (e.g., "1111") that mimic official Solana system accounts. Taking advantage of wallet software that only displays partial addresses, they deceive victims into signing transactions interacting with these counterfeit addresses, under the pretense of engaging with legitimate system accounts.

## Key Findings

- **8,058** instances of SolPhish detected
- Nearly **$1.1 million** in losses caused to victims
- Comprehensive analysis of:
  - Distribution and impact of SolPhish
  - Characteristics of the phishers
  - Relationships among phishing gangs

## Citation

If you use this code or dataset in your research, please cite:

```bibtex
@ARTICLE{11320875,
  author={Li, Ziwei and Jiang, Zigui and Fang, Ming and Chen, Jiaxin and Wu, Zhiying and Wu, Jiajing and Zhang, Lun and Zheng, Zibin},
  journal={IEEE Transactions on Information Forensics and Security}, 
  title={SolPhishHunter: Toward Detecting and Understanding Phishing on Solana}, 
  year={2026},
  volume={21},
  number={},
  pages={757-771},
  doi={10.1109/TIFS.2025.3649957}}
