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


public class QueryParameters {

    @QueryValue("values")
    private final Map<String, String> parameters;

    public QueryParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    @Override
    public String toString() {
        return parameters.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining(", ", "{", "}"));
    }
}

//动态条件构建
public class FilterExpressionBuilder {

	public Op eq(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.EQ, new Key(key), new Value(value)));
	}

	public Op ne(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.NE, new Key(key), new Value(value)));
	}

	public Op gt(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.GT, new Key(key), new Value(value)));
	}

	public Op gte(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.GTE, new Key(key), new Value(value)));
	}

	public Op lt(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.LT, new Key(key), new Value(value)));
	}

	public Op lte(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.LTE, new Key(key), new Value(value)));
	}

	public Op and(Op left, Op right) {
		return new Op(new Filter.Expression(ExpressionType.AND, left.expression, right.expression));
	}

	public Op or(Op left, Op right) {
		return new Op(new Filter.Expression(ExpressionType.OR, left.expression, right.expression));
	}

	public Op in(String key, Object... values) {
		return this.in(key, List.of(values));
	}

	public Op in(String key, List<Object> values) {
		return new Op(new Filter.Expression(ExpressionType.IN, new Key(key), new Value(values)));
	}

	public Op nin(String key, Object... values) {
		return this.nin(key, List.of(values));
	}

	public Op nin(String key, List<Object> values) {
		return new Op(new Filter.Expression(ExpressionType.NIN, new Key(key), new Value(values)));
	}

	public Op group(Op content) {
		return new Op(new Filter.Group(content.build()));
	}

	public Op not(Op content) {
		return new Op(new Filter.Expression(ExpressionType.NOT, content.expression, null));
	}

	public record Op(Filter.Operand expression) {

		public Filter.Expression build() {
			if (this.expression instanceof Filter.Group group) {
				// Remove the top-level grouping.
				return group.content();
			}
			else if (this.expression instanceof Filter.Expression exp) {
				return exp;
			}
			throw new RuntimeException("Invalid expression: " + this.expression);
		}

	}

}


//链式流程定义
private ApiCall<ApiResponse<AlbumObject>, ApiException> prepareGetAnAlbumRequest(
            final String id,
            final String market) throws IOException {
        return new ApiCall.Builder<ApiResponse<AlbumObject>, ApiException>()
                .globalConfig(getGlobalConfiguration())
                .requestBuilder(requestBuilder -> requestBuilder
                        .server(Server.ENUM_DEFAULT.value())
                        .path("/albums/{id}")
                        .queryParam(param -> param.key("market")
                                .value(market).isRequired(false))
                        .templateParam(param -> param.key("id").value(id)
                                .shouldEncode(true))
                        .headerParam(param -> param.key("accept").value("application/json"))
                        .withAuth(auth -> auth
                                .add("oauth_2_0"))
                        .arraySerializationFormat(ArraySerializationFormat.CSV)
                        .httpMethod(HttpMethod.GET)
                )
                .responseHandler(responseHandler -> responseHandler
                        .responseClassType(ResponseClassType.API_RESPONSE)
                        .apiResponseDeserializer(
                                response -> ApiHelper.deserialize(response, AlbumObject.class))
                        .nullify404(false)
                        .localErrorCase("401",
                                ErrorCase.setReason("Bad or expired token. This can happen if the user revoked a token or\nthe access token has expired. You should re-authenticate the user.\n",
                                        (reason, context) -> new UnauthorizedException(reason, context)))
                        .localErrorCase("403",
                                ErrorCase.setReason("Bad OAuth request (wrong consumer key, bad nonce, expired\ntimestamp...). Unfortunately, re-authenticating the user won't help here.\n",
                                        (reason, context) -> new ForbiddenException(reason, context)))
                        .localErrorCase("429",
                                ErrorCase.setReason("The app has exceeded its rate limits.\n",
                                        (reason, context) -> new TooManyRequestsException(reason, context)))
                        .globalErrorCase(GLOBAL_ERROR_CASES))
                .build();
    }

 //user请求自动符值
  @Bean
  @Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
  public User.UserBuilder callerBuilder() {
    return User.builder();
  }

//factory返回值不固定
public interface HttpClientFactory<T> {

    T create(HttpClientSettings settings);

}
//aws-sdk-java
public class ApacheHttpClientFactory implements HttpClientFactory<ConnectionManagerAwareHttpClient> {
}

//eventstore expression
   void testSelectWhere() {
        SelectBuilder builder = new SelectBuilder(database, of(COL_T1_01, COL_T1_02, COL_T1_03));
        builder.from(TABLE_T1);
        builder.where(eq(COL_T1_02));
        assertEquals("SELECT col_T1_01,col_T1_02,col_T1_03 FROM T1 WHERE col_T1_02=?", builder.<SqlQuery>build().sql());

        builder = new SelectBuilder(database, of(COL_T1_01, COL_T1_02, COL_T1_03));
        builder.from(TABLE_T1);
        builder.where(and(eq(COL_T1_02), eq(COL_T1_03)));
        assertEquals("SELECT col_T1_01,col_T1_02,col_T1_03 FROM T1 WHERE (col_T1_02=? AND col_T1_03=?)", builder.<SqlQuery>build().sql());
    }

//enenvstrorm antlr4
    public static PageRequest parse(String query, EvaluatorDefinition evaluatorDefinition) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("parseQuery [{}]", query);
        }

        if (Strings.isEmpty(query)) {
            throw new PageRequestException(PageRequestException.Type.EMPTY, ImmutableMap.of());
        }

        RequestContext ctx = parse(query);

        PageRequestBuilder builder = parseRange(query, ctx.range());
        parseFilter(builder, ctx.filter(), evaluatorDefinition);
        parseSort(builder, ctx.sort());

        builder.withEvaluator(evaluatorDefinition);

        return builder.build();
    }

