use anchor_lang::prelude::*;

declare_id!("3qkLJYYQfXK1GJWkPicuNtQnsme5WoZYkUfdqYrGrc1y");

#[program]
pub mod sentinel_guardian {
    use super::*;

    /// Called once by a protocol to register with SentinelGuard.
    /// They deposit SOL into the bounty escrow at this point.
    pub fn register_protocol(
        ctx: Context<RegisterProtocol>,
        escrow_amount: u64,
    ) -> Result<()> {
        let sentinel_key = ctx.accounts.sentinel_state.key();
        let sentinel_info = ctx.accounts.sentinel_state.to_account_info();
    
        let protocol_info = ctx.accounts.protocol_authority.to_account_info();
    
        let state = &mut ctx.accounts.sentinel_state;
    
        state.protocol_address = ctx.accounts.protocol_authority.key();
        state.paused = false;
        state.pause_count = 0;
        state.last_pause_ts = 0;
        state.escrow_balance = escrow_amount;
        state.authority = ctx.accounts.watcher_authority.key();
        state.bump = ctx.bumps.sentinel_state;
    
        // Transfer SOL
        if escrow_amount > 0 {
            let ix = anchor_lang::solana_program::system_instruction::transfer(
                &protocol_info.key(),
                &sentinel_key,
                escrow_amount,
            );
    
            anchor_lang::solana_program::program::invoke(
                &ix,
                &[
                    protocol_info,
                    sentinel_info, 
                ],)?;
        }
    
        Ok(())
    }
    /// Called by the watcher binary when an exploit is detected.
    /// This is the critical path — must be fast.
    pub fn pause_withdrawals(
        ctx: Context<PauseWithdrawals>,
        alert_id: [u8; 32],
        severity: u8,
        estimated_at_risk: u64,
    ) -> Result<()> {
        let state = &mut ctx.accounts.sentinel_state;

        // Only the registered watcher authority can pause
        require!(
            ctx.accounts.watcher.key() == state.authority,
            SentinelError::UnauthorizedWatcher
        );

        require!(!state.paused, SentinelError::AlreadyPaused);

        state.paused = true;
        state.pause_count += 1;
        state.last_pause_ts = Clock::get()?.unix_timestamp;

        // Record the alert on-chain
        let alert = &mut ctx.accounts.alert_record;
        alert.alert_id = alert_id;
        alert.protocol = state.protocol_address;
        alert.severity = severity;
        alert.estimated_at_risk = estimated_at_risk;
        alert.watcher = ctx.accounts.watcher.key();
        alert.validated = false;
        alert.bounty_claimed = false;
        alert.timestamp = state.last_pause_ts;
        alert.bump = ctx.bumps.alert_record;

        emit!(PauseEvent {
            protocol: state.protocol_address,
            alert_id,
            severity,
            estimated_at_risk,
            slot: Clock::get()?.slot,
        });

        msg!(
            "PAUSE FIRED — protocol: {}, severity: {}, at_risk: {}",
            state.protocol_address,
            severity,
            estimated_at_risk
        );
        Ok(())
    }

    /// Called by the protocol team (multisig) after reviewing the alert.
    /// Only the original protocol_authority can unpause.
    pub fn unpause_withdrawals(ctx: Context<UnpauseWithdrawals>) -> Result<()> {
        let state = &mut ctx.accounts.sentinel_state;
        require!(state.paused, SentinelError::NotPaused);
        state.paused = false;

        msg!("Protocol unpaused by authority: {}", ctx.accounts.protocol_authority.key());
        Ok(())
    }

    /// Protocol team calls this to validate an alert was real.
    /// Enables the watcher to claim their bounty.
    pub fn validate_alert(ctx: Context<ValidateAlert>) -> Result<()> {
        let alert = &mut ctx.accounts.alert_record;
        require!(!alert.validated, SentinelError::AlreadyValidated);
        alert.validated = true;

        msg!("Alert validated: {:?}", alert.alert_id);
        Ok(())
    }

    /// Watcher calls this after alert is validated to collect bounty.
    pub fn claim_bounty(
        ctx: Context<ClaimBounty>,
        alert_id: [u8; 32],
    ) -> Result<()> {
        let alert = &ctx.accounts.alert_record;
        let state = &mut ctx.accounts.sentinel_state;

        require!(alert.validated, SentinelError::AlertNotValidated);
        require!(!alert.bounty_claimed, SentinelError::BountyAlreadyClaimed);
        require!(
            ctx.accounts.watcher.key() == alert.watcher,
            SentinelError::UnauthorizedWatcher
        );
        require!(alert.alert_id == alert_id, SentinelError::AlertMismatch);

        // Pay 10% of escrow as bounty (configurable later)
        let bounty_amount = state.escrow_balance / 10;
        require!(state.escrow_balance >= bounty_amount, SentinelError::InsufficientEscrow);

        state.escrow_balance -= bounty_amount;

        // Transfer from PDA to watcher
        **ctx.accounts.sentinel_state.to_account_info().try_borrow_mut_lamports()? -= bounty_amount;
        **ctx.accounts.watcher.to_account_info().try_borrow_mut_lamports()? += bounty_amount;

        // Mark claimed — need mut ref after the immutable borrow above
        let alert = &mut ctx.accounts.alert_record;
        alert.bounty_claimed = true;

        msg!("Bounty claimed: {} lamports by {}", bounty_amount, ctx.accounts.watcher.key());
        Ok(())
    }
}

// ─── Accounts ───────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct RegisterProtocol<'info> {
    #[account(
        init,
        payer = protocol_authority,
        space = 8 + SentinelState::INIT_SPACE,
        seeds = [b"sentinel", protocol_authority.key().as_ref()],
        bump
    )]
    pub sentinel_state: Account<'info, SentinelState>,

    #[account(mut)]
    pub protocol_authority: Signer<'info>,

    /// CHECK: This is the watcher keypair pubkey — stored for authorization
    pub watcher_authority: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(alert_id: [u8; 32])]
pub struct PauseWithdrawals<'info> {
    #[account(
        mut,
        seeds = [b"sentinel", sentinel_state.protocol_address.as_ref()],
        bump = sentinel_state.bump
    )]
    pub sentinel_state: Account<'info, SentinelState>,

    #[account(
        init,
        payer = watcher,
        space = 8 + AlertRecord::INIT_SPACE,
        seeds = [b"alert", alert_id.as_ref()],
        bump
    )]
    pub alert_record: Account<'info, AlertRecord>,

    #[account(mut)]
    pub watcher: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnpauseWithdrawals<'info> {
    #[account(
        mut,
        seeds = [b"sentinel", protocol_authority.key().as_ref()],
        bump = sentinel_state.bump
    )]
    pub sentinel_state: Account<'info, SentinelState>,

    pub protocol_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ValidateAlert<'info> {
    #[account(
        seeds = [b"sentinel", protocol_authority.key().as_ref()],
        bump = sentinel_state.bump
    )]
    pub sentinel_state: Account<'info, SentinelState>,

    #[account(mut)]
    pub alert_record: Account<'info, AlertRecord>,

    pub protocol_authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(alert_id: [u8; 32])]
pub struct ClaimBounty<'info> {
    #[account(
        mut,
        seeds = [b"sentinel", sentinel_state.protocol_address.as_ref()],
        bump = sentinel_state.bump
    )]
    pub sentinel_state: Account<'info, SentinelState>,

    #[account(
        mut,
        seeds = [b"alert", alert_id.as_ref()],
        bump = alert_record.bump
    )]
    pub alert_record: Account<'info, AlertRecord>,

    #[account(mut)]
    pub watcher: Signer<'info>,
}

// ─── State ───────────────────────────────────────────────────────────────────

#[account]
#[derive(InitSpace)]
pub struct SentinelState {
    pub protocol_address: Pubkey,   // the pool/vault being guarded
    pub paused: bool,               // THE flag — protocols check this
    pub pause_count: u64,           // analytics
    pub last_pause_ts: i64,         // unix timestamp
    pub escrow_balance: u64,        // bounty escrow in lamports
    pub authority: Pubkey,          // watcher keypair that can pause
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AlertRecord {
    pub alert_id: [u8; 32],         // sha256(tx_sig + slot)
    pub protocol: Pubkey,
    pub severity: u8,               // 0-100
    pub estimated_at_risk: u64,     // lamports equivalent
    pub watcher: Pubkey,            // who detected (for bounty)
    pub validated: bool,            // protocol team confirmed real
    pub bounty_claimed: bool,
    pub timestamp: i64,
    pub bump: u8,
}

// ─── Events ──────────────────────────────────────────────────────────────────

#[event]
pub struct PauseEvent {
    pub protocol: Pubkey,
    pub alert_id: [u8; 32],
    pub severity: u8,
    pub estimated_at_risk: u64,
    pub slot: u64,
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[error_code]
pub enum SentinelError {
    #[msg("Caller is not the registered watcher authority")]
    UnauthorizedWatcher,
    #[msg("Protocol is already paused")]
    AlreadyPaused,
    #[msg("Protocol is not paused")]
    NotPaused,
    #[msg("Alert has already been validated")]
    AlreadyValidated,
    #[msg("Alert has not been validated by protocol team")]
    AlertNotValidated,
    #[msg("Bounty has already been claimed for this alert")]
    BountyAlreadyClaimed,
    #[msg("Alert ID does not match the record")]
    AlertMismatch,
    #[msg("Insufficient escrow balance for bounty payout")]
    InsufficientEscrow,
}
