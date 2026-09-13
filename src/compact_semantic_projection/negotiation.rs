//! Explicit compatibility selection for compact projection v1 and model-text v2 wires.

/// Bounded negotiation input. Each offer names only existing wire facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionOffer {
    pub format_version: u32,
    pub encoding: ProjectionEncoding,
    pub profile: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProjectionEncoding {
    Binary,
    Text,
    ModelText,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionAgreement {
    pub format_version: u32,
    pub encoding: ProjectionEncoding,
    pub profile: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegotiationRefusal {
    OfferLimit,
    UnsupportedVersion,
    UnsupportedProfile,
    UnsupportedEncoding,
    NoCommonOffer,
}

pub const MAX_OFFERS: usize = 16;
const PROFILES: &[&str] = &[
    "agent-context-v2",
    "agent-definition-graph",
    "api-surface-v8-owned-data",
    "candidate-semantic-delta-catalog",
    "full-graph",
    "task-context-v1",
];

/// Selects the lexicographically earliest common profile, preferring binary
/// over text. Inputs are sets semantically: their order cannot affect output.
pub fn negotiate(
    local: &[ProjectionOffer],
    peer: &[ProjectionOffer],
) -> Result<ProjectionAgreement, NegotiationRefusal> {
    if local.len() > MAX_OFFERS || peer.len() > MAX_OFFERS {
        return Err(NegotiationRefusal::OfferLimit);
    }
    validate(local)?;
    validate(peer)?;
    let mut common: Vec<_> = local.iter().filter(|offer| peer.contains(offer)).collect();
    common.sort_by(|a, b| a.profile.cmp(&b.profile).then(a.encoding.cmp(&b.encoding)));
    common
        .first()
        .map(|offer| ProjectionAgreement {
            format_version: offer.format_version,
            encoding: offer.encoding,
            profile: offer.profile.clone(),
        })
        .ok_or(NegotiationRefusal::NoCommonOffer)
}

fn validate(offers: &[ProjectionOffer]) -> Result<(), NegotiationRefusal> {
    for offer in offers {
        if !matches!(
            offer.format_version,
            super::FORMAT_VERSION | super::MODEL_TEXT_FORMAT_VERSION
        ) {
            return Err(NegotiationRefusal::UnsupportedVersion);
        }
        let supported = match offer.encoding {
            ProjectionEncoding::Binary | ProjectionEncoding::Text => {
                offer.format_version == super::FORMAT_VERSION
            }
            ProjectionEncoding::ModelText => {
                offer.format_version == super::MODEL_TEXT_FORMAT_VERSION
            }
        };
        if !supported {
            return Err(NegotiationRefusal::UnsupportedEncoding);
        }
        if !PROFILES.contains(&offer.profile.as_str()) {
            return Err(NegotiationRefusal::UnsupportedProfile);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn offer(profile: &str, encoding: ProjectionEncoding) -> ProjectionOffer {
        ProjectionOffer {
            format_version: 1,
            encoding,
            profile: profile.into(),
        }
    }
    #[test]
    fn order_does_not_change_selection() {
        let a = vec![
            offer("full-graph", ProjectionEncoding::Text),
            offer("agent-context-v2", ProjectionEncoding::Binary),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(negotiate(&a, &b).unwrap().profile, "agent-context-v2");
    }
    #[test]
    fn unsupported_facts_fail_closed() {
        assert_eq!(
            negotiate(
                &[ProjectionOffer {
                    format_version: 99,
                    encoding: ProjectionEncoding::Text,
                    profile: "full-graph".into()
                }],
                &[]
            ),
            Err(NegotiationRefusal::UnsupportedVersion)
        );
        assert_eq!(
            negotiate(&[offer("unknown", ProjectionEncoding::Text)], &[]),
            Err(NegotiationRefusal::UnsupportedProfile)
        );
    }
    #[test]
    fn model_text_requires_its_own_version_and_exact_common_offer() {
        let model = ProjectionOffer {
            format_version: 2,
            encoding: ProjectionEncoding::ModelText,
            profile: "full-graph".into(),
        };
        assert_eq!(
            negotiate(std::slice::from_ref(&model), std::slice::from_ref(&model))
                .unwrap()
                .format_version,
            2
        );
        assert_eq!(
            negotiate(
                std::slice::from_ref(&model),
                &[offer("full-graph", ProjectionEncoding::Text)]
            ),
            Err(NegotiationRefusal::NoCommonOffer)
        );
        let invalid = ProjectionOffer {
            format_version: 1,
            ..model
        };
        assert_eq!(
            negotiate(&[invalid], &[]),
            Err(NegotiationRefusal::UnsupportedEncoding)
        );
    }
    #[test]
    fn offer_bound_is_enforced() {
        let offers = vec![offer("full-graph", ProjectionEncoding::Text); MAX_OFFERS + 1];
        assert_eq!(negotiate(&offers, &[]), Err(NegotiationRefusal::OfferLimit));
    }
}
