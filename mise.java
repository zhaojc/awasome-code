org.springframework.ai.chat.client.advisor.RetrievalAugmentationAdvisor
//异步任务
public AdvisedRequest before(AdvisedRequest request) {
		Map<String, Object> context = new HashMap<>(request.adviseContext());

		// 0. Create a query from the user text, parameters, and conversation history.
		Query originalQuery = Query.builder()
			.text(new PromptTemplate(request.userText(), request.userParams()).render())
			.history(request.messages())
			.build();

		// 1. Transform original user query based on a chain of query transformers.
		Query transformedQuery = originalQuery;
		for (var queryTransformer : this.queryTransformers) {
			transformedQuery = queryTransformer.apply(transformedQuery);
		}

		// 2. Expand query into one or multiple queries.
		List<Query> expandedQueries = this.queryExpander != null ? this.queryExpander.expand(transformedQuery)
				: List.of(transformedQuery);

		// 3. Get similar documents for each query.
		Map<Query, List<List<Document>>> documentsForQuery = expandedQueries.stream()
			.map(query -> CompletableFuture.supplyAsync(() -> getDocumentsForQuery(query), this.taskExecutor))
			.toList()
			.stream()
			.map(CompletableFuture::join)
			.collect(Collectors.toMap(Map.Entry::getKey, entry -> List.of(entry.getValue())));

		// 4. Combine documents retrieved based on multiple queries and from multiple data
		// sources.
		List<Document> documents = this.documentJoiner.join(documentsForQuery);
		context.put(DOCUMENT_CONTEXT, documents);

		// 5. Augment user query with the document contextual data.
		Query augmentedQuery = this.queryAugmenter.augment(originalQuery, documents);

		// 6. Update advised request with augmented prompt.
		return AdvisedRequest.from(request).userText(augmentedQuery.text()).adviseContext(context).build();
	}  
