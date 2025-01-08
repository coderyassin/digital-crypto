package org.yascode.encryption;

public class CertificateInformation {
    private String commonName;
    private String organizationalUnit;
    private String organization;
    private String locality;
    private String state;
    private String country;

    private CertificateInformation(Builder builder) {
        this.commonName = builder.commonName;
        this.organizationalUnit = builder.organizationalUnit;
        this.organization = builder.organization;
        this.locality = builder.locality;
        this.state = builder.state;
        this.country = builder.country;
    }

    public String getCommonName() {
        return commonName;
    }

    public String getOrganizationalUnit() {
        return organizationalUnit;
    }

    public String getOrganization() {
        return organization;
    }

    public String getLocality() {
        return locality;
    }

    public String getState() {
        return state;
    }

    public String getCountry() {
        return country;
    }

    public static class Builder {
        private String commonName;
        private String organizationalUnit;
        private String organization;
        private String locality;
        private String state;
        private String country;

        public Builder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        public Builder organizationalUnit(String organizationalUnit) {
            this.organizationalUnit = organizationalUnit;
            return this;
        }

        public Builder organization(String organization) {
            this.organization = organization;
            return this;
        }

        public Builder locality(String locality) {
            this.locality = locality;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder country(String country) {
            this.country = country;
            return this;
        }

        public CertificateInformation build() {
            return new CertificateInformation(this);
        }
    }
}
