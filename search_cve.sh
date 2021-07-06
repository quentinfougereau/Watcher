#!/bin/bash

CVE_DATA_FEEDS=https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz
CVE_ARCHIVE="nvdcve-1.1-recent.json.gz"
CVE_JSON="nvdcve-1.1-recent.json"
CVE_FOUND_JSON="cve_found.txt"


# Download and uncompress recent CVEs file
wget "$CVE_DATA_FEEDS" -O "$CVE_ARCHIVE"
gzip -df "$CVE_ARCHIVE"

if [ -f "$CVE_FOUND_JSON" ]
then
    rm $CVE_FOUND_JSON
fi

touch $CVE_FOUND_JSON

# Search if components are present in recent CVEs file
while read -r component
do
    IFS=':'
    read -a component_arr <<< $component
    product=${component_arr[0]}
    version=${component_arr[1]}
    IFS=
    echo -e "\n--- $component ---\n" >> $CVE_FOUND_JSON
    cat "$CVE_JSON" | \
    jq '.CVE_Items[]? |
      	select(
        		[.configurations.nodes[]? | .cpe_match[]?, .children[]?.cpe_match[]? |
        		(
          			(.cpe23Uri | contains("'"$component"'")) or
          			( (.cpe23Uri | test("[aoh]:[a-zA-Z1-9-_]+:'"$product"':\\*")) and
            				(
              					(. | has("versionEndIncluding") and .versionEndIncluding >= "'"$version"'") or
              					(. | has("versionEndExcluding") and .versionEndExcluding > "'"$version"'")
            				)
          			)
        		)] | any
        ) |
    	{id: .cve.CVE_data_meta.ID } |
    	.reference="https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + .id' >> $CVE_FOUND_JSON
done < "components.txt"

# Count total number of CVE
count=$(grep -c '"id":' $CVE_FOUND_JSON)
sed -i '1iWe found '$count' cve that may impact your project.\n' $CVE_FOUND_JSON
