package com.dreamsecurity.demo.util;

public class Constants {
	public enum ValidityType {
		DAY("DAY"),
		MONTH("MONTH"),
		YEAR("YEAR");
		
		private String validityType;
		
		private ValidityType(String validityType) {
			this.setValidityType(validityType);
		}

		public String getValidityType() {
			return validityType;
		}

		public void setValidityType(String validityType) {
			this.validityType = validityType;
		}
	}
}
