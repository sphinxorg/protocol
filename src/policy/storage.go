// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/storage.go
package policy

import (
	"math/big"
)

const bytesPerGiB = uint64(1024 * 1024 * 1024)

// CalculateStorageCostExact returns the policy charge for retaining bytes for
// whole months. All arithmetic is integer nSPX, making it safe to use for
// consensus accounting as well as client estimates.
func (p *PolicyParameters) CalculateStorageCostExact(bytes, months uint64) *StoragePricing {
	if p == nil || p.PinRatePerGBMonth == nil || bytes == 0 || months == 0 {
		return &StoragePricing{Bytes: bytes, DurationDays: months * 30, CostPerMonth: big.NewInt(0), TotalCost: big.NewInt(0)}
	}
	// Round up partial GiB usage so a non-empty persistent artifact always
	// pays for its retained storage allocation.
	numerator := new(big.Int).Mul(p.PinRatePerGBMonth, new(big.Int).SetUint64(bytes))
	divisor := new(big.Int).SetUint64(bytesPerGiB)
	costPerMonth := new(big.Int).Add(numerator, new(big.Int).Sub(divisor, big.NewInt(1)))
	costPerMonth.Div(costPerMonth, divisor)
	return &StoragePricing{
		Bytes: bytes, DurationDays: months * 30,
		CostPerMonth: costPerMonth,
		TotalCost:    new(big.Int).Mul(costPerMonth, new(big.Int).SetUint64(months)),
	}
}

// CalculateStorageCost calculates the cost for storing data
func (p *PolicyParameters) CalculateStorageCost(bytes uint64, months float64) *StoragePricing {
	if months <= 0 {
		return p.CalculateStorageCostExact(bytes, 0)
	}
	return p.CalculateStorageCostExact(bytes, uint64(months))
}

// CalculatePinningCost calculates the cost for pinning data (long-term storage)
func (p *PolicyParameters) CalculatePinningCost(bytes uint64, months uint64) *big.Int {
	return p.CalculateStorageCostExact(bytes, months).TotalCost
}
