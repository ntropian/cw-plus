use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use cosmwasm_std::{
    attr, Addr, CustomQuery, Deps, DepsMut, MessageInfo, Response, StdError, StdResult,
};
use cw_storage_plus::Map;

/// Returned from RANKS.query_rank()
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct RankResponse {
    pub address_rank: Option<u8>, //more than 255 ranks seems impractical
}

/// Errors returned from RANKS
#[derive(Error, Debug, PartialEq)]
pub enum RanksError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Caller has no rank")]
    NoRank {},

    #[error("Caller rank too low")]
    RankTooLow {},

    #[error("Caller cannot change their own rank")]
    CannotSetOwnRank {},
}

// state/logic
// an IndexedMap might make sense later so that admins of a given level can be easily pulled
pub struct Ranks<'a>(Map<'a, &'a str, u8>);

// this is the core business logic we expose
impl<'a> Ranks<'a> {
    pub const fn new(namespace: &'a str) -> Self {
        Ranks(Map::new(namespace))
    }

    pub fn set<Q: CustomQuery>(
        &self,
        deps: DepsMut<Q>,
        address: Addr,
        address_rank: u8,
    ) -> StdResult<()> {
        self.0
            .save(deps.storage, &address.to_string(), &address_rank)
    }

    pub fn get<Q: CustomQuery>(&self, deps: Deps<Q>, address: Addr) -> StdResult<Option<u8>> {
        match self.0.load(deps.storage, &address.to_string()) {
            Ok(val) => Ok(Some(val)),
            Err(StdError::NotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Returns Ok(true) if this is an address of the indicated rank or higher,
    /// Ok(false) if not, and an Error if we hit an error with Api or Storage usage
    pub fn is_rank<Q: CustomQuery>(
        &self,
        deps: Deps<Q>,
        caller: &Addr,
        required_rank: u8,
    ) -> StdResult<bool> {
        match self.0.load(deps.storage, &caller.to_string()) {
            Ok(rank) => Ok(rank >= required_rank),
            Err(StdError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Like is_rank but returns RanksError::RankTooLow if rank is <= required_rank.
    /// Helper for a nice one-line auth check.
    pub fn assert_rank<Q: CustomQuery>(
        &self,
        deps: Deps<Q>,
        caller: &Addr,
        required_rank: u8,
    ) -> Result<(), RanksError> {
        if !self.is_rank(deps, caller, required_rank)? {
            Err(RanksError::RankTooLow {})
        } else {
            Ok(())
        }
    }

    pub fn execute_update_rank<C, Q: CustomQuery>(
        &self,
        deps: DepsMut<Q>,
        info: MessageInfo,
        target_address: Addr,
        new_rank: u8,
    ) -> Result<Response<C>, RanksError>
    where
        C: Clone + fmt::Debug + PartialEq + JsonSchema,
    {
        // only addresses of >= rank than the target rank can access this
        let caller_rank = self.get(deps.as_ref(), info.sender.clone())?;
        let unwrapped_caller_rank = match caller_rank {
            Some(rank) => {
                if rank < new_rank {
                    return Err(RanksError::RankTooLow {});
                }
                rank
            }
            None => {
                return Err(RanksError::NoRank {});
            }
        };

        // address cannot set their own rank
        if info.sender == target_address {
            return Err(RanksError::CannotSetOwnRank {});
        }

        // address cannot reduce rank of a higher or equal address
        if let Some(rank) = self.get(deps.as_ref(), target_address.clone())? {
            if rank <= unwrapped_caller_rank {
                return Err(RanksError::RankTooLow {});
            }
        }

        let attributes = vec![
            attr("action", "update_rank"),
            attr("address", target_address.to_string()),
            attr("rank", new_rank.to_string()),
            attr("sender", info.sender),
        ];

        self.set(deps, target_address, new_rank)?;

        Ok(Response::new().add_attributes(attributes))
    }

    pub fn query_rank(&self, deps: Deps, address: Addr) -> StdResult<RankResponse> {
        let address_rank = self.get(deps, address)?;
        Ok(RankResponse { address_rank })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_info};
    use cosmwasm_std::Empty;

    #[test]
    fn set_and_get_rank() {
        let mut deps = mock_dependencies();
        let control = Ranks::new("foo");

        // initialize and check
        let address = Addr::unchecked("admin");
        control.set(deps.as_mut(), address.clone(), 10u8).unwrap();
        let got = control.get(deps.as_ref(), address.clone()).unwrap();
        assert_eq!(Some(10u8), got);
    }

    #[test]
    fn rank_checks() {
        let mut deps = mock_dependencies();

        let control = Ranks::new("foo");
        let rank10 = Addr::unchecked("big boss");
        let rank9 = Addr::unchecked("small boss");
        let imposter = Addr::unchecked("imposter");

        // ensure checks proper, including "rank >=" checks
        control.set(deps.as_mut(), rank10.clone(), 10).unwrap();
        control.set(deps.as_mut(), rank9.clone(), 9).unwrap();

        assert!(control.is_rank(deps.as_ref(), &rank10, 10u8).unwrap());
        assert!(control.is_rank(deps.as_ref(), &rank9, 9u8).unwrap());
        assert!(control.is_rank(deps.as_ref(), &rank9, 8u8).unwrap());

        assert!(!(control.is_rank(deps.as_ref(), &rank10, 11u8).unwrap()));
        assert!(!(control.is_rank(deps.as_ref(), &rank9, 10u8).unwrap()));
        assert!(!(control.is_rank(deps.as_ref(), &imposter, 1u8).unwrap()));

        control.assert_rank(deps.as_ref(), &rank10, 10u8).unwrap();
        let err = control
            .assert_rank(deps.as_ref(), &imposter, 3u8)
            .unwrap_err();
        assert_eq!(RanksError::RankTooLow {}, err);
    }

    #[test]
    fn test_execute_query() {
        let mut deps = mock_dependencies();

        // initial setup
        let control = Ranks::new("foo");
        let rank10 = Addr::unchecked("big boss");
        let rank9 = Addr::unchecked("small boss");
        let imposter = Addr::unchecked("imposter");
        let friend = Addr::unchecked("buddy");
        control.set(deps.as_mut(), rank10.clone(), 10u8).unwrap();

        // query shows results
        let res = control.query_rank(deps.as_ref(), rank10.clone()).unwrap();
        assert_eq!(Some(10u8), res.address_rank);

        // imposter cannot update
        let info = mock_info(imposter.as_ref(), &[]);
        let err = control
            .execute_update_rank::<Empty, Empty>(deps.as_mut(), info, friend.clone(), 5u8)
            .unwrap_err();
        assert_eq!(RanksError::NoRank {}, err);

        // rank10 can update
        let info = mock_info(rank10.as_ref(), &[]);
        let res = control
            .execute_update_rank::<Empty, Empty>(deps.as_mut(), info, friend.clone(), 5u8)
            .unwrap();
        assert_eq!(0, res.messages.len());

        // rank10 cannot promote to higher rank than self
        let info = mock_info(rank10.as_ref(), &[]);
        let err = control
            .execute_update_rank::<Empty, Empty>(deps.as_mut(), info, rank9.clone(), 15u8)
            .unwrap_err();
        assert_eq!(RanksError::RankTooLow {}, err);

        // rank10 can demote rank9
        let info = mock_info(rank10.as_ref(), &[]);
        let res = control
            .execute_update_rank::<Empty, Empty>(deps.as_mut(), info, rank9.clone(), 8u8)
            .unwrap();
        assert_eq!(0, res.messages.len());

        // rank10 cannot update self
        let info = mock_info(rank10.as_ref(), &[]);
        let err = control
            .execute_update_rank::<Empty, Empty>(deps.as_mut(), info, rank10.clone(), 5u8)
            .unwrap_err();
        assert_eq!(RanksError::CannotSetOwnRank {}, err);

        // rank9 cannot demote rank10
        let info = mock_info(rank9.as_ref(), &[]);
        let res = control
            .execute_update_rank::<Empty, Empty>(deps.as_mut(), info, rank10.clone(), 5u8)
            .unwrap();
        assert_eq!(0, res.messages.len());

        // query shows results
        let res = control.query_rank(deps.as_ref(), friend.clone()).unwrap();
        assert_eq!(Some(5u8), res.address_rank);
        // we demoted rank9 to rank 8 up above
        let res = control.query_rank(deps.as_ref(), rank9.clone()).unwrap();
        assert_eq!(Some(8u8), res.address_rank);
    }
}
