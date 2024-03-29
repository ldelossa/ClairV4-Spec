# Usage

This portion of documentation explains how to use ClairV4 as a client.  
Read this to understand how ClairV4 works at a high level.  

## Modes

ClairV4 has several node types called **Modes**.  
Currently implemented **Modes** include:  

### indexer 

Fetching and indexing **claircore.Manifest** contents for searching and vulnerability matching

### matcher
Periodically updates the vulnerability database.  
Identifies vulnerabilities found in a **claircore.IndexReport**.  

## Logical Overview

A **claircore.Manifest** should be crafted with information about your container.  
A **POST** of this data structure should be done to a ClairV4 node in **indexer** mode.   

The indexer will begin to index the layer contents of your submitted **claircore.Manifest**.  
On successful index a **claircore.IndexReport** will be returned.  
From a client's point of view the returned **claircore.IndexReport** is largely information.  
If the HTTP status code is not 200-OK the returned **claircore.IndexReport** will provide a detailed issue as to why the index operation failed.  

Now that the **claircore.Manifest** has been indexed a **GET** may be issued to a ClairV4 node in **matcher** mode.  
When the **GET** is issued this node will retrieve the **claircore.IndexReport** from a ClairV4 node in **indexer** mode and return a **claircore.VulnerabilityReport** providing the vulnerabilities found within the coalesced image's contents.  

## API 

The follow section shows the client facing API usage.   
Refer to [api](./api.md) section for full object schemas.  

### Index a claircore.Manifest (Indexer Mode)
see [Layer](./api.md#layer)  

    /api/v1/index
    POST

    {
    	"hash": <string>,
    	"layers": [
    		{
    			"hash": <string>,
    			"remote_path": {
    				"uri": <string>,
    				"headers": <map<string><[]string>>
    			}
    		},
    		...
    	]
    }

### Retrieve IndexReport (Indexer Mode)  
see [IndexReport](./api.md#IndexReport/IndexRecord)  

    /api/v1/index_report/{manifest_hash}  
    GET

    returned
    <IndexReport>

### Match for Vulnerabilities (Matcher Mode)
see [Package](./api.md#Package)  
    [Vulnerability](./api.md#Vulnerability)  

    /api/v1/match/{manifest_hash}
    GET

    returned

    // claircore.VulnerabilityReport
    {
    	"hash": <string>,
    	"vulnerabilities": <map<int><Vulnerability>>,
    	"details": <map<int><Details>>
    }
    
    // claircore.Details
    {
    	"affected_package": <Package>,
    	"introduced_in": <string>,
    	"fixed_in_version": <string>
    }
