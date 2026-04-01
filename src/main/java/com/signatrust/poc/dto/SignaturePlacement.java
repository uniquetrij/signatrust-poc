package com.signatrust.poc.dto;

public class SignaturePlacement {
    private int pageNumber = 1;
    private float positionX = 50f;
    private float positionY = 50f;
    private float rotation = 0f;

    public SignaturePlacement() {}

    public int getPageNumber() { return pageNumber; }
    public void setPageNumber(int pageNumber) { this.pageNumber = pageNumber; }

    public float getPositionX() { return positionX; }
    public void setPositionX(float positionX) { this.positionX = positionX; }

    public float getPositionY() { return positionY; }
    public void setPositionY(float positionY) { this.positionY = positionY; }

    public float getRotation() { return rotation; }
    public void setRotation(float rotation) { this.rotation = rotation; }
}
