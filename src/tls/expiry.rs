use std::time::SystemTime;

#[derive(Debug, PartialEq)]
pub enum CertExpiryStatus {
    Ok,
    ExpiringSoon { days_remaining: i64 },
    Expired,
}

pub fn check_cert_expiry(not_after: SystemTime) -> CertExpiryStatus {
    let now = SystemTime::now();
    match not_after.duration_since(now) {
        Ok(remaining) => {
            let days = remaining.as_secs() / 86400;
            if days <= 14 {
                CertExpiryStatus::ExpiringSoon {
                    days_remaining: days as i64,
                }
            } else {
                CertExpiryStatus::Ok
            }
        }
        Err(_) => CertExpiryStatus::Expired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn cert_expiry_ok_when_more_than_14_days() {
        // Use 20 days to avoid off-by-one from integer truncation near boundary
        let not_after = SystemTime::now() + Duration::from_secs(20 * 86400);
        assert_eq!(check_cert_expiry(not_after), CertExpiryStatus::Ok);
    }

    #[test]
    fn cert_expiry_expiring_soon_within_14_days() {
        // Use 5 days — well within the 14-day warning window
        let not_after = SystemTime::now() + Duration::from_secs(5 * 86400);
        assert!(
            matches!(
                check_cert_expiry(not_after),
                CertExpiryStatus::ExpiringSoon { days_remaining: d } if d <= 5
            ),
            "expected ExpiringSoon within 5 days"
        );
    }

    #[test]
    fn cert_expiry_expired_when_in_past() {
        let not_after = SystemTime::now() - Duration::from_secs(1);
        assert_eq!(check_cert_expiry(not_after), CertExpiryStatus::Expired);
    }
}
