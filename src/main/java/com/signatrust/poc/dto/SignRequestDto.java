package com.signatrust.poc.dto;

import java.util.List;

public class SignRequestDto {
    private String signerName;
    private String location;
    private List<SignaturePlacement> placements;

    public SignRequestDto() {}

    public String getSignerName() { return signerName; }
    public void setSignerName(String signerName) { this.signerName = signerName; }

    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }

    public List<SignaturePlacement> getPlacements() { return placements; }
    public void setPlacements(List<SignaturePlacement> placements) { this.placements = placements; }
}
