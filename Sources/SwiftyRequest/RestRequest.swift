/**
 * Copyright IBM Corporation 2016,2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Foundation
import CircuitBreaker
import LoggerAPI
import NIOHTTPClient
import NIO
import NIOHTTP1
import NIOSSL

/// Object containing everything needed to build and execute HTTP requests.
public class RestRequest {

    deinit {
        try? session.syncShutdown()
    }
    
    // Check if there exists a self-signed certificate and whether it's a secure connection
    private let isSecure: Bool
    private let isSelfSigned: Bool
    

    /// A default `HTTPClient` instance.
    private var session: HTTPClient

    // The HTTP Request
    private var request: HTTPClient.Request

    /// The currently configured `CircuitBreaker` instance for this `RestRequest`. In order to create a
    /// `CircuitBreaker` you should set the `circuitParameters` property.
    internal(set) public var circuitBreaker: CircuitBreaker<(HTTPClient.Request, (Result<HTTPClient.Response, Error>) -> Void), String>?

    /// Parameters for a `CircuitBreaker` instance.
    /// When these parameters are set, a new `circuitBreaker` instance is created.
    ///
    /// ### Usage Example: ###
    /// ```swift
    /// let circuitParameters = CircuitParameters(timeout: 2000,
    ///                                           maxFailures: 2,
    ///                                           fallback: breakFallback)
    ///
    /// let request = RestRequest(method: .GET, url: "http://myApiCall/hello")
    /// request.circuitParameters = circuitParameters
    /// ```
    public var circuitParameters: CircuitParameters<String>? = nil {
        didSet {
            if let params = circuitParameters {
                circuitBreaker = CircuitBreaker(name: params.name,
                                                timeout: params.timeout,
                                                resetTimeout: params.resetTimeout,
                                                maxFailures: params.maxFailures,
                                                rollingWindow: params.rollingWindow,
                                                bulkhead: params.bulkhead,
                                                // We capture a weak reference to self to prevent a retain cycle from `handleInvocation` -> RestRequest` -> `circuitBreaker` -> `handleInvocation`. To do this we have explicitly declared the handleInvocation function as a closure.
                                                command: { [weak self] invocation in self?.handleInvocation(invocation: invocation) },
                                                fallback: params.fallback)
            }
        }
    }

    // MARK: HTTP Request Parameters
    /// URL `String` used to store a url containing replaceable template values.
    private var urlTemplate: String?

    /// The string representation of the HTTP request url.
    private var url: String

    /// The HTTP method specified in the request, defaults to GET.
    ///
    /// ### Usage Example: ###
    /// ```swift
    /// request.method = .PUT
    /// ```
    public var method: HTTPMethod {
        get {
            return request.method
        }
        set {
            request.method = newValue
        }
    }

    /// The HTTP authentication credentials for the request.
    ///
    /// ### Usage Example: ###
    /// The example below uses an API key to specify the authentication credentials. You can also use `.bearerAuthentication`
    /// and pass in a base64 encoded String as the token, or `.basicAuthentication` where the username and password values to
    /// authenticate with are passed in.
    ///
    /// ```swift
    /// let request = RestRequest(url: "http://localhost:8080")
    /// request.credentials = .basicAuthentication(username: "Hello", password: "World")
    /// ```
    public var credentials: Credentials? {
        didSet {
            // set the request's authentication credentials
            if let credentials = credentials {
                request.headers.replaceOrAdd(name: "Authorization", value: credentials.authheader)
            } else {
                request.headers.remove(name: "Authorization")
            }
        }
    }

    /// The HTTP header fields which form the header section of the request message.
    ///
    /// The header fields set using this parameter will be added to the existing headers.
    ///
    /// ### Usage Example: ###
    ///
    /// ```swift
    /// request.headerParameters = HTTPHeaders([("Cookie", "v1")])
    /// ```
    public var headerParameters: HTTPHeaders {
        get {
            return request.headers
        }
        set {
            request.headers.add(contentsOf: newValue)
        }
    }

    /// The HTTP `Accept` header, i.e. the media type that is acceptable for the response, it defaults to
    /// "application/json".
    ///
    /// ### Usage Example: ###
    /// ```swift
    /// request.acceptType = "text/html"
    /// ```
    public var acceptType: String? {
        get {
            return request.headers["Accept"].first
        }
        set {
            if let value = newValue {
                request.headers.replaceOrAdd(name: "Accept", value: value)
            } else {
                request.headers.remove(name: "Accept")
            }
        }
    }

    /// HTTP `Content-Type` header, i.e. the media type of the body of the request, it defaults to
    /// "application/json".
    ///
    /// ### Usage Example: ###
    /// ```swift
    /// request.contentType = "application/x-www-form-urlencoded"
    /// ```
    public var contentType: String? {
        get {
            return request.headers["Content-Type"].first
        }
        set {
            if let value = newValue {
                request.headers.replaceOrAdd(name: "Content-Type", value: value)
            } else {
                request.headers.remove(name: "Content-Type")
            }
        }
    }

    /// HTTP `User-Agent` header, i.e. the user agent string of the software that is acting on behalf of the user.
    /// If you pass in `<productName>/<productVersion>` the value will be set to
    /// `<productName>/<productVersion> <operatingSystem>/<operatingSystemVersion>`.
    ///
    /// ### Usage Example: ###
    /// ```swift
    /// request.productInfo = "swiftyrequest-sdk/2.0.4"
    /// ```
    public var productInfo: String? {
        get {
            return request.headers["User-Agent"].first
        }
        set {
            if let value = newValue {
                request.headers.replaceOrAdd(name: "User-Agent", value: value.generateUserAgent())
            } else {
                request.headers.remove(name: "User-Agent")
            }
        }
    }

    /// The HTTP message body, i.e. the body of the request.
    ///
    /// ### Usage Example: ###
    /// ```swift
    /// request.messageBody = data
    /// ``
    public var messageBody: Data? {
        get {
            switch request.body {
            case .data(let body)?:
                return body
            case .string(let body)?:
                return Data(body.utf8)
            case .byteBuffer(let body)?:
                if let bytes = body.getBytes(at: 0, length: body.readableBytes) {
                    return Data(bytes)
                } else {
                    return nil
                }
            default:
                return nil
            }
        }
        set {
            if let data = newValue {
                request.body = .data(data)
            } else {
                request.body = nil
            }
        }
    }

    /// The HTTP query items to specify in the request URL. If there are query items already specified in the request URL they
    /// will be replaced.
    ///
    /// ### Usage Example: ###
    /// ```swift
    /// request.queryItems = [
    ///                        URLQueryItem(name: "flamingo", value: "pink"),
    ///                        URLQueryItem(name: "seagull", value: "white")
    ///                      ]
    /// ```
    public var queryItems: [URLQueryItem]?  {
        set {
            if let updatedURL = setQueryItems(url: request.url, queryItems: newValue) {
                request.url = updatedURL
            } 
        }
        get {
            if let urlComponents = URLComponents(url: request.url, resolvingAgainstBaseURL: false) {
                return urlComponents.queryItems
            }
            return nil
        }
    }
    
    // Replace queryitems on request.url with new queryItems
    private func setQueryItems(url: URL, queryItems: [URLQueryItem]?) -> URL? {
        if var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            urlComponents.queryItems = queryItems
            // Must encode "+" to %2B (URLComponents does not do this)
            urlComponents.percentEncodedQuery = urlComponents.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
            return urlComponents.url 
        } else {
            return nil
        }
    }

    /// Initialize a `RestRequest` instance.
    ///
    /// ### Usage Example: ###
    /// ```swift
    /// let request = RestRequest(method: .GET, url: "http://myApiCall/hello")
    /// ```
    ///
    /// - Parameters:
    ///   - method: The method specified in the request, defaults to GET.
    ///   - url: URL string to use for the network request.
    ///   - containsSelfSignedCert: Pass `True` to use self signed certificates.
    ///   - clientCertificate: Pass in `ClientCertificate` with the certificate name and path to use client certificates for 2-way SSL.
    public init(method: HTTPMethod = .GET, url: String, containsSelfSignedCert: Bool = false) throws {

        self.isSecure = url.hasPrefix("https")
        self.isSelfSigned = containsSelfSignedCert

        // Instantiate basic mutable request
        if url.contains("{") {
            // Is a template URL which is not valid and will be replaced so use temporary value
            self.request = try HTTPClient.Request(url: "http://template")
            self.urlTemplate = url
        } else {
            self.request = try HTTPClient.Request(url: url)
        }
        if containsSelfSignedCert {
            self.session =  HTTPClient(eventLoopGroupProvider: .createNew, configuration: HTTPClient.Configuration(certificateVerification: .none))
        } else {
            self.session = HTTPClient(eventLoopGroupProvider: .createNew)
        }

        // Set initial fields
        self.url = url
        
        self.method = method
        self.acceptType = "application/json"
        self.contentType = "application/json"

    }

    // MARK: Response methods
    /// Request response method that either invokes `CircuitBreaker` or executes the HTTP request.
    ///
    /// - Parameter completionHandler: Callback used on completion of operation.
    public func response(completionHandler: @escaping (Result<HTTPClient.Response, Error>) -> Void) {
        response(request: self.request, completionHandler: completionHandler)
    }
    
    func response(request: HTTPClient.Request, completionHandler: @escaping (Result<HTTPClient.Response, Error>) -> Void) {
        if let breaker = circuitBreaker {
            breaker.run(commandArgs: (request, completionHandler), fallbackArgs: "Circuit is open")
        } else {
            self.session.execute(request: request).whenComplete { result in
                completionHandler(result)
            }
        }
    }

    /// Request response method with the expected result of a `Data` object.
    ///
    /// - Parameters:
    ///   - templateParams: URL templating parameters used for substituion if possible.
    ///   - queryItems: Sets the query parameters for this RestRequest, overwriting any existing parameters. Defaults to `nil`, which means that this parameter will be ignored, and `RestRequest.queryItems` will be used instead. Note that if you wish to clear any existing query parameters, then you should set `request.queryItems = nil` before calling this function.
    ///   - completionHandler: Callback used on completion of operation.
    public func responseData(templateParams: [String: String]? = nil,
                             queryItems: [URLQueryItem]? = nil,
                             completionHandler: @escaping (Result<RestResponse<Data>, Error>) -> Void) {

        var request = self.request
        
        guard let url = performSubstitutions(params: templateParams),
            let host = url.host,
            let scheme = url.scheme
        else {
            return completionHandler(.failure(RestError.invalidSubstitution))
        }
        request.url = url
        request.host = host
        request.scheme = scheme
        
        // Replace any existing query items with those provided in the queryItems
        // parameter, if any were given.
        if let query = queryItems, let queryURL = setQueryItems(url: request.url, queryItems: query) {
            request.url = queryURL
        }

        response(request: request) { result in
            switch result {
            case .failure(let error):
                return completionHandler(.failure(error))
            case .success(let response):
                guard let body = response.body,
                    let bodyBytes = body.getBytes(at: 0, length: body.readableBytes)
                else {
                    return completionHandler(.failure(RestError.noData(response: response)))
                }
                return completionHandler(.success(RestResponse(host: response.host,
                                                        status: response.status,
                                                        headers: response.headers,
                                                        body: Data(bodyBytes)))) 
            }
        }
    }

    /// Request response method with the expected result of the object `T` specified.
    ///
    /// - Parameters:
    ///   - templateParams: URL templating parameters used for substitution if possible.
    ///   - queryItems: Sets the query parameters for this RestRequest, overwriting any existing parameters. Defaults to `nil`, which means that this parameter will be ignored, and `RestRequest.queryItems` will be used instead. Note that if you wish to clear any existing query parameters, then you should set `request.queryItems = nil` before calling this function.
    ///   - completionHandler: Callback used on completion of operation.
    public func responseObject<T: Decodable>(templateParams: [String: String]? = nil,
                                             queryItems: [URLQueryItem]? = nil,
                                             completionHandler: @escaping (Result<RestResponse<T>, Error>) -> Void) {

        var request = self.request
        
        guard let url = performSubstitutions(params: templateParams),
            let host = url.host,
            let scheme = url.scheme
            else {
                return completionHandler(.failure(RestError.invalidSubstitution))
        }
        request.url = url
        request.host = host
        request.scheme = scheme
        
        // Replace any existing query items with those provided in the queryItems
        // parameter, if any were given.
        if let query = queryItems, let queryURL = setQueryItems(url: request.url, queryItems: query) {
            request.url = queryURL
        }
        
        response(request: request) { result in
            switch result {
            case .failure(let error):
                return completionHandler(.failure(error))
            case .success(let response):
                guard let body = response.body,
                    let bodyBytes = body.getBytes(at: 0, length: body.readableBytes)
                else {
                    return completionHandler(.failure(RestError.noData(response: response)))
                }
                do {
                    let object = try JSONDecoder().decode(T.self, from: Data(bodyBytes))
                    return completionHandler(.success(RestResponse(host: response.host,
                                                            status: response.status,
                                                            headers: response.headers,
                                                            body: object))) 
                } catch {
                    return completionHandler(.failure(RestError.decodingError(error: error, response: response)))
                }
            }
        }
    }

    /// Request response method with the expected result of an array of `Any` JSON.
    ///
    /// - Parameters:
    ///   - templateParams: URL templating parameters used for substitution if possible.
    ///   - queryItems: Sets the query parameters for this RestRequest, overwriting any existing parameters. Defaults to `nil`, which means that this parameter will be ignored, and `RestRequest.queryItems` will be used instead. Note that if you wish to clear any existing query parameters, then you should set `request.queryItems = nil` before calling this function.
    ///   - completionHandler: Callback used on completion of operation.
    public func responseArray(templateParams: [String: String]? = nil,
                              queryItems: [URLQueryItem]? = nil,
                              completionHandler: @escaping (Result<RestResponse<[Any]>, Error>) -> Void) {
        
        var request = self.request
        
        guard let url = performSubstitutions(params: templateParams),
            let host = url.host,
            let scheme = url.scheme
            else {
                return completionHandler(.failure(RestError.invalidSubstitution))
        }
        request.url = url
        request.host = host
        request.scheme = scheme
        
        // Replace any existing query items with those provided in the queryItems
        // parameter, if any were given.
        if let query = queryItems, let queryURL = setQueryItems(url: request.url, queryItems: query) {
            request.url = queryURL
        }
        
        response(request: request) { result in
            switch result {
            case .failure(let error):
                return completionHandler(.failure(error))
            case .success(let response):
                guard let body = response.body,
                    let bodyBytes = body.getBytes(at: 0, length: body.readableBytes)
                else {
                    return completionHandler(.failure(RestError.noData(response: response)))
                }
                guard let object = (try? JSONSerialization.jsonObject(with: Data(bodyBytes))) as? [Any] else {
                    return completionHandler(.failure(RestError.serializationError(response: response)))
                }
                return completionHandler(.success(RestResponse(host: response.host,
                                                               status: response.status,
                                                               headers: response.headers,
                                                               body: object))) 
            }
        }
    }
    
    /// Request response method with the expected result of a `[String: Any]` JSON dictionary.
    ///
    /// - Parameters:
    ///   - templateParams: URL templating parameters used for substitution if possible.
    ///   - queryItems: Sets the query parameters for this RestRequest, overwriting any existing parameters. Defaults to `nil`, which means that this parameter will be ignored, and `RestRequest.queryItems` will be used instead. Note that if you wish to clear any existing query parameters, then you should set `request.queryItems = nil` before calling this function.
    ///   - completionHandler: Callback used on completion of operation.
    public func responseDictionary(templateParams: [String: String]? = nil,
                              queryItems: [URLQueryItem]? = nil,
                              completionHandler: @escaping (Result<RestResponse<[String: Any]>, Error>) -> Void) {
        
        var request = self.request
        
        guard let url = performSubstitutions(params: templateParams),
            let host = url.host,
            let scheme = url.scheme
            else {
                return completionHandler(.failure(RestError.invalidSubstitution))
        }
        request.url = url
        request.host = host
        request.scheme = scheme
        
        // Replace any existing query items with those provided in the queryItems
        // parameter, if any were given.
        if let query = queryItems, let queryURL = setQueryItems(url: request.url, queryItems: query) {
            request.url = queryURL
        }
        
        response(request: request) { result in
            switch result {
            case .failure(let error):
                return completionHandler(.failure(error))
            case .success(let response):
                guard let body = response.body,
                    let bodyBytes = body.getBytes(at: 0, length: body.readableBytes)
                    else {
                        return completionHandler(.failure(RestError.noData(response: response)))
                }
                guard let object = (try? JSONSerialization.jsonObject(with: Data(bodyBytes))) as? [String: Any] else {
                    return completionHandler(.failure(RestError.serializationError(response: response)))
                }
                return completionHandler(.success(RestResponse(host: response.host,
                                                               status: response.status,
                                                               headers: response.headers,
                                                               body: object))) 
            }
        }
    }


    /// Request response method with the expected result of a `String`.
    ///
    /// - Parameters:
    ///   - templateParams: URL templating parameters used for substituion if possible.
    ///   - queryItems: Sets the query parameters for this RestRequest, overwriting any existing parameters. Defaults to `nil`, which means that this parameter will be ignored, and `RestRequest.queryItems` will be used instead. Note that if you wish to clear any existing query parameters, then you should set `request.queryItems = nil` before calling this function.
    ///   - completionHandler: Callback used on completion of operation.
    public func responseString(templateParams: [String: String]? = nil,
                               queryItems: [URLQueryItem]? = nil,
                               completionHandler: @escaping (Result<RestResponse<String>, Error>) -> Void) {
        
        var request = self.request
        
        guard let url = performSubstitutions(params: templateParams),
            let host = url.host,
            let scheme = url.scheme
            else {
                return completionHandler(.failure(RestError.invalidSubstitution))
        }
        request.url = url
        request.host = host
        request.scheme = scheme
        
        // Replace any existing query items with those provided in the queryItems
        // parameter, if any were given.
        if let query = queryItems, let queryURL = setQueryItems(url: request.url, queryItems: query) {
            request.url = queryURL
        }
        
        response(request: request) { result in
            switch result {
            case .failure(let error):
                return completionHandler(.failure(error))
            case .success(let response):
                guard let body = response.body,
                    let bodyBytes = body.getBytes(at: 0, length: body.readableBytes)
                    else {
                        return completionHandler(.failure(RestError.noData(response: response)))
                }
                // Retrieve string encoding type
                let encoding = self.getCharacterEncoding(from: response.headers["Content-Type"].first)
                
                guard let object = String(bytes: bodyBytes, encoding: encoding) else {
                    return completionHandler(.failure(RestError.serializationError(response: response)))
                }
                return completionHandler(.success(RestResponse(host: response.host,
                                                               status: response.status,
                                                               headers: response.headers,
                                                               body: object))) 
            }
        }
    }

    /// Request response method to use when there is no expected result.
    ///
    /// - Parameters:
    ///   - templateParams: URL templating parameters used for substituion if possible.
    ///   - queryItems: Sets the query parameters for this RestRequest, overwriting any existing parameters. Defaults to `nil`, which means that this parameter will be ignored, and `RestRequest.queryItems` will be used instead. Note that if you wish to clear any existing query parameters, then you should set `request.queryItems = nil` before calling this function.
    ///   - completionHandler: Callback used on completion of operation.
    public func responseVoid(templateParams: [String: String]? = nil,
                             queryItems: [URLQueryItem]? = nil,
                             completionHandler: @escaping (Result<HTTPClient.Response, Error>) -> Void) {
        
        var request = self.request
        
        guard let url = performSubstitutions(params: templateParams),
            let host = url.host,
            let scheme = url.scheme
            else {
                return completionHandler(.failure(RestError.invalidSubstitution))
        }
        request.url = url
        request.host = host
        request.scheme = scheme
        
        // Replace any existing query items with those provided in the queryItems
        // parameter, if any were given.
        if let query = queryItems, let queryURL = setQueryItems(url: request.url, queryItems: query) {
            request.url = queryURL
        }
        
        response(request: request) { result in
            switch result {
            case .failure(let error):
                return completionHandler(.failure(error))
            case .success(let response):
                return completionHandler(.success(response)) 
            }
        }
    }

    class DownloadDelegate: HTTPClientResponseDelegate {
        typealias Response = HTTPResponseHead
        
        var count = 0
        let destination: URL
        var responseHead: HTTPResponseHead?
        var error: Error?
        
        init(destination: URL) {
            self.destination = destination
        }
        
        func didTransmitRequestBody(task: HTTPClient.Task<HTTPResponseHead>) {
            // this is executed when request is sent, called once
            // Create a file in one doesn't exist
            do {
                try "".write(to: destination, atomically: true, encoding: .utf8)
            } catch {
                self.error = error
            }
        }
        
        func didReceiveHead(task: HTTPClient.Task<HTTPResponseHead>, _ head: HTTPResponseHead) {
            // this is executed when we receive HTTP Reponse head part of the request (it contains response code and headers), called once
            self.responseHead = head
        }
        
        func didReceivePart(task: HTTPClient.Task<HTTPResponseHead>, _ buffer: ByteBuffer) {
            // this is executed when we receive parts of the response body, could be called zero or more times
            do {
                let fileHandle = try FileHandle(forUpdating: destination)
                fileHandle.seekToEndOfFile()
                fileHandle.write(Data(buffer.getBytes(at: 0, length: buffer.readableBytes) ?? []))
                fileHandle.closeFile()
            } catch {
                self.error = error
            }
        }
        
        func didFinishRequest(task: HTTPClient.Task<HTTPResponseHead>) throws -> HTTPResponseHead {
            // this is called when the request is fully read, called once
            // this is where you return a result or throw any errors you require to propagate to the client
            guard let head = responseHead else {
                throw RestError.downloadError
            }
            if let error = error {
                throw error
            }
            return head
        }
        
        func didReceiveError(task: HTTPClient.Task<HTTPResponseHead>, _ error: Error) {
            // this is called when we receive any network-related error, called once
            self.error = error
        }
    }
    
    /// Utility method to download a file from a remote origin.
    ///
    /// - Parameters:
    ///   - destination: URL destination to save the file to.
    ///   - completionHandler: Callback used on completion of the operation.
    public func download(to destination: URL, completionHandler: @escaping (Result<HTTPResponseHead, Error>) -> Void) {
        let delegate = DownloadDelegate(destination: destination)
        
        session.execute(request: request, delegate: delegate).future.whenComplete({ result in
            completionHandler(result)
        })
    }

    /// Method used by `CircuitBreaker` as the contextCommand.
    ///
    /// - Parameter invocation: `Invocation` contains a command argument, `Void` return type, and a `String` fallback arguement.
    private func handleInvocation(invocation: Invocation<(HTTPClient.Request, (Result<HTTPClient.Response, Error>) -> Void), String>) {
        self.session.execute(request: invocation.commandArgs.0).whenComplete { result in
            switch result {
            case .failure(let error):
                invocation.notifyFailure(error: BreakerError(reason: error.localizedDescription))
            case .success(_):
                invocation.notifySuccess()
            }
            let callback = invocation.commandArgs.1
            callback(result)
        }
    }

    /// Method to perform substitution on `String` URL if it contains templated placeholders
    ///
    /// - Parameter params: dictionary of parameters to substitute in
    /// - Returns: returns either a `RestError` or nil if there were no problems setting new URL on our `URLRequest` object
    private func performSubstitutions(params: [String: String]?) -> URL? {

        guard let templateURL = self.urlTemplate else {
            // No templating required
            return self.request.url
        } 
        
        guard let params = params else {
            // Expected to replace values but no template provided
            return nil
        }
        
        // Get urlTemplate if available, otherwise just use the request's url
        let urlString = templateURL.expandString(params: params)

        // Confirm that the resulting URL is valid
        guard let newURL = URL(string: urlString) else {
            // Expected to replace values but no template provided
            return nil
        }
        
        return newURL
        
    }

    /// Method to identify the charset encoding defined by the Content-Type header
    /// - Defaults set to .utf8
    /// - Parameter contentType: The content-type header string
    /// - Returns: returns the defined or default String.Encoding.Type
    private func getCharacterEncoding(from contentType: String? = nil) -> String.Encoding {
        guard let text = contentType,
              let regex = try? NSRegularExpression(pattern: "(?<=charset=).*?(?=$|;|\\s)", options: [.caseInsensitive]),
              let match = regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).last,
              let range = Range(match.range, in: text) else {
            return .utf8
        }

        /// Strip whitespace and quotes
        let charset = String(text[range]).trimmingCharacters(in: CharacterSet(charactersIn: "\"").union(.whitespaces))

        switch String(charset).lowercased() {
        case "iso-8859-1": return .isoLatin1
        default: return .utf8
        }
    }
}

/// Encapsulates properties needed to initialize a `CircuitBreaker` object within the `RestRequest` initializer.
/// `A` is the type of the fallback's parameter.
public struct CircuitParameters<A> {

    /// The circuit name: defaults to "circuitName".
    let name: String

    /// The circuit timeout: defaults to 2000.
    public let timeout: Int

    /// The circuit timeout: defaults to 60000.
    public let resetTimeout: Int

    /// Max failures allowed: defaults to 5.
    public let maxFailures: Int

    /// Rolling Window: defaults to 10000.
    public let rollingWindow:Int

    /// Bulkhead: defaults to 0.
    public let bulkhead: Int

    /// The error fallback callback.
    public let fallback: (BreakerError, A) -> Void

    /// Initialize a `CircuitParameters` instance.
    public init(name: String = "circuitName", timeout: Int = 2000, resetTimeout: Int = 60000, maxFailures: Int = 5, rollingWindow: Int = 10000, bulkhead: Int = 0, fallback: @escaping (BreakerError, A) -> Void) {
        self.name = name
        self.timeout = timeout
        self.resetTimeout = resetTimeout
        self.maxFailures = maxFailures
        self.rollingWindow = rollingWindow
        self.bulkhead = bulkhead
        self.fallback = fallback
    }
}

/// Struct used to specify the type of authentication being used.
public struct Credentials {
    
    let authheader: String

    /// Note: The bearer token should be base64 encoded.
    public static func bearerAuthentication(token: String) -> Credentials {
        return Credentials(authheader: "Bearer \(token)")
    }
    

    /// A basic username/password authentication is being used with the values passed in.
    public static func basicAuthentication(username: String, password: String) -> Credentials {
        let authData = Data((username + ":" + password).utf8)
        let authString = authData.base64EncodedString()
        return Credentials(authheader: "Basic \(authString)")
    }
}
