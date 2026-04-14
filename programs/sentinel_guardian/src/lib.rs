use anchor_lang::prelude::*;

declare_id!("3qkLJYYQfXK1GJWkPicuNtQnsme5WoZYkUfdqYrGrc1y");

#[program]
pub mod sentinel_guardian {
    use super::*;

    pub fn register_protocol(
        ctx: Context<RegisterProtocol>,
        escrow_amount: u64,
    ) -> Result<()> {
    
        
        let sentinel_info = ctx.accounts.sentinel_state.to_account_info();
        let protocol_info = ctx.accounts.protocol_authority.to_account_info();
    
        
        if escrow_amount > 0 {
            let cpi_ctx = CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: protocol_info.clone(),    
                    to: sentinel_info.clone(),     
                },
            );
            anchor_lang::system_program::transfer(cpi_ctx, escrow_amount)?;
        }
    
        // ✅ STEP 3: NOW take mutable borrow (SAFE)
        let state = &mut ctx.accounts.sentinel_state;
    
        state.protocol_address = ctx.accounts.protocol_authority.key();
        state.paused = false;
        state.pause_count = 0;
        state.last_pause_ts = 0;
        state.escrow_balance = escrow_amount;
        state.authority = ctx.accounts.watcher_authority.key();
        state.bump = ctx.bumps.sentinel_state;
    
        msg!(
            "Protocol registered: {}, watcher: {}, escrow: {}",
            state.protocol_address,
            state.authority,
            escrow_amount
        );
    
        Ok(())
    }

    pub fn pause_withdrawals(
        ctx: Context<PauseWithdrawals>,
        alert_id: [u8; 32],
        severity: u8,
        rule_triggered: u8,         // which rule fired
        estimated_at_risk: u64,
    ) -> Result<()> {
        let state = &mut ctx.accounts.sentinel_state;

        require!(
            ctx.accounts.watcher.key() == state.authority,
            SentinelError::UnauthorizedWatcher
        );
        require!(!state.paused, SentinelError::AlreadyPaused);

        state.paused = true;
        state.pause_count += 1;
        state.last_pause_ts = Clock::get()?.unix_timestamp;

        let alert = &mut ctx.accounts.alert_record;
        alert.alert_id = alert_id;
        alert.protocol = state.protocol_address;
        alert.severity = severity;
        alert.rule_triggered = rule_triggered;
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
            rule_triggered,
            estimated_at_risk,
            slot: Clock::get()?.slot,
        });

        msg!(
            "PAUSE FIRED — protocol: {}, severity: {}, rule: {}, at_risk: {}",
            state.protocol_address,
            severity,
            rule_triggered,
            estimated_at_risk
        );
        Ok(())
    }

    pub fn unpause_withdrawals(ctx: Context<UnpauseWithdrawals>) -> Result<()> {
        let state = &mut ctx.accounts.sentinel_state;
        require!(state.paused, SentinelError::NotPaused);
        state.paused = false;

        emit!(UnpauseEvent {
            protocol: state.protocol_address,
            unpaused_by: ctx.accounts.protocol_authority.key(),
            slot: Clock::get()?.slot,
        });

        msg!("Protocol unpaused by: {}", ctx.accounts.protocol_authority.key());
        Ok(())
    }
   
    pub fn validate_alert(ctx: Context<ValidateAlert>) -> Result<()> {
        let alert = &mut ctx.accounts.alert_record;
        require!(!alert.validated, SentinelError::AlreadyValidated);
        alert.validated = true;
        msg!("Alert validated: {:?}", alert.alert_id);
        Ok(())
    }

    pub fn claim_bounty(
        ctx: Context<ClaimBounty>,
        alert_id: [u8; 32],
    ) -> Result<()> {
        // Read everything first — no borrow conflict
        let validated = ctx.accounts.alert_record.validated;
        let bounty_claimed = ctx.accounts.alert_record.bounty_claimed;
        let alert_watcher = ctx.accounts.alert_record.watcher;
        let stored_alert_id = ctx.accounts.alert_record.alert_id;
        let alert_protocol = ctx.accounts.alert_record.protocol;

        require!(validated, SentinelError::AlertNotValidated);
        require!(!bounty_claimed, SentinelError::BountyAlreadyClaimed);
        require!(
            ctx.accounts.watcher.key() == alert_watcher,
            SentinelError::UnauthorizedWatcher
        );
        require!(stored_alert_id == alert_id, SentinelError::AlertMismatch);
        // Defense in depth: alert must belong to this protocol's escrow
        require!(
            alert_protocol == ctx.accounts.sentinel_state.protocol_address,
            SentinelError::AlertMismatch
        );

        let bounty_amount = ctx.accounts.sentinel_state.escrow_balance / 10;
        require!(
            ctx.accounts.sentinel_state.escrow_balance >= bounty_amount,
            SentinelError::InsufficientEscrow
        );

        // Transfer lamports from PDA to watcher
        **ctx.accounts.sentinel_state.to_account_info().try_borrow_mut_lamports()? -= bounty_amount;
        **ctx.accounts.watcher.to_account_info().try_borrow_mut_lamports()? += bounty_amount;

        // Now mutably borrow to update state
        ctx.accounts.sentinel_state.escrow_balance -= bounty_amount;
        ctx.accounts.alert_record.bounty_claimed = true;

        msg!(
            "Bounty claimed: {} lamports by {}",
            bounty_amount,
            ctx.accounts.watcher.key()
        );
        Ok(())
    }
}

// ─── Accounts ────────────────────────────────────────────────────────────────

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

    /// CHECK: Watcher pubkey — stored for pause authorization
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

    pub system_program: Program<'info, System>,  // required for alert_record init
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
    pub protocol_address: Pubkey,
    pub paused: bool,
    pub pause_count: u64,
    pub last_pause_ts: i64,
    pub escrow_balance: u64,
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AlertRecord {
    pub alert_id: [u8; 32],
    pub protocol: Pubkey,
    pub severity: u8,
    pub rule_triggered: u8,       // 1=flash_loan, 2=tvl_velocity, 3=bridge_spike
    pub estimated_at_risk: u64,
    pub watcher: Pubkey,
    pub validated: bool,
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
    pub rule_triggered: u8,
    pub estimated_at_risk: u64,
    pub slot: u64,
}

#[event]
pub struct UnpauseEvent {
    pub protocol: Pubkey,
    pub unpaused_by: Pubkey,
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
