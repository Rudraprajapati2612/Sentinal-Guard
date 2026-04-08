use anchor_lang::prelude::*;

declare_id!("3qkLJYYQfXK1GJWkPicuNtQnsme5WoZYkUfdqYrGrc1y");

#[program]
pub mod sentinel_guard {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
